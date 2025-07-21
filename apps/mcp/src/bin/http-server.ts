#!/usr/bin/env node

/**
 * HTTP Server for MCP Proxy with Streamable HTTP support
 * Provides REST API and real-time streaming for LLM communication
 */

import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { ProxyMcpServer } from '../manager/proxy-mcp-server.js';
import { ConfigurationManager } from '../manager/configuration-manager.js';
import { getConfigFromCommanderAndEnv } from './config.js';

// Helper function to safely get error message
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

interface McpHttpServer {
  app: express.Application;
  server: any;
  io: SocketIOServer;
  proxyServer: ProxyMcpServer;
}

export class McpHttpServerManager {
  private httpServer?: McpHttpServer;
  private port: number;

  constructor(port: number = 3001) {
    this.port = port;
  }

  async initialize(): Promise<void> {
    this.httpServer = await this.createHttpServer();
  }

  private async createHttpServer(): Promise<McpHttpServer> {
    const app = express();
    const server = createServer(app);
    const io = new SocketIOServer(server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Load configuration
    const toolsetConfig = getConfigFromCommanderAndEnv();
    const configManager = new ConfigurationManager();
    
    // Create proxy server with async initialization
    console.error("🚀 Initializing HTTP MCP Proxy Server...");
    const proxyServer = await ProxyMcpServer.create({
      name: "mcp-proxy-http",
      version: "1.0.0",
      toolsetConfig: toolsetConfig.toolsetConfig || { mode: "readWrite" },
      dynamicToolDiscovery: toolsetConfig.dynamicToolDiscovery || { enabled: true },
      configurationManager: configManager,
    });

    // Middleware
    app.use(cors());
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));

    // Setup routes
    this.setupRoutes(app, proxyServer, io);
    this.setupSocketHandlers(io, proxyServer);

    return { app, server, io, proxyServer };
  }

  private setupRoutes(app: express.Application, proxyServer: ProxyMcpServer, io: SocketIOServer) {
    // Setup OAuth routes with CORS support
    this.setupOAuthRoutes(app, proxyServer);
    
    // Health check
    app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      });
    });

    // MCP Protocol endpoints
    app.get('/mcp/servers', async (req, res) => {
      try {
        const servers = proxyServer.backend.getAllConnections().map(conn => ({
          id: conn.config.id,
          name: conn.config.name,
          description: conn.config.description,
          status: conn.status,
          enabled: conn.config.enabled,
          transportType: conn.config.transportType,
          toolCount: conn.tools.size,
          resourceCount: conn.resources.size,
          promptCount: conn.prompts.size
        }));
        res.json({ servers });
      } catch (error) {
        res.status(500).json({ error: 'Failed to list servers' });
      }
    });

    app.get('/mcp/servers/:serverId/tools', async (req, res) => {
      try {
        const { serverId } = req.params;
        const connection = proxyServer.backend.getServerConnection(serverId);
        
        if (!connection) {
          return res.status(404).json({ error: 'Server not found' });
        }

        const tools = Array.from(connection.tools.values());
        res.json({ tools });
      } catch (error) {
        res.status(500).json({ error: 'Failed to list tools' });
      }
    });

    app.post('/mcp/tools/call', async (req, res) => {
      try {
        const { toolName, arguments: args } = req.body;
        
        // Extract server ID and tool name from the proxy format
        const [serverId, actualToolName] = toolName.split('__');
        
        if (!serverId || !actualToolName) {
          return res.status(400).json({ error: 'Invalid tool name format' });
        }

        const result = await proxyServer.backend.callTool(serverId, actualToolName, args);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: 'Failed to call tool', details: getErrorMessage(error) });
      }
    });

    // Configuration management endpoints
    app.get('/mcp/config', async (req, res) => {
      try {
        const config = proxyServer.config.getConfiguration();
        res.json(config);
      } catch (error) {
        res.status(500).json({ error: 'Failed to get configuration' });
      }
    });

    app.post('/mcp/config/servers', async (req, res) => {
      try {
        const serverConfig = req.body;
        proxyServer.config.addServer(serverConfig);
        
        // Notify clients about server changes
        io.emit('serverAdded', serverConfig);
        
        res.json({ success: true, message: 'Server added successfully' });
      } catch (error) {
        res.status(500).json({ error: 'Failed to add server', details: getErrorMessage(error) });
      }
    });

    app.delete('/mcp/config/servers/:serverId', async (req, res) => {
      try {
        const { serverId } = req.params;
        proxyServer.config.removeServer(serverId);
        
        // Notify clients about server changes
        io.emit('serverRemoved', { serverId });
        
        res.json({ success: true, message: 'Server removed successfully' });
      } catch (error) {
        res.status(500).json({ error: 'Failed to remove server' });
      }
    });

    app.put('/mcp/config/servers/:serverId/enable', async (req, res) => {
      try {
        const { serverId } = req.params;
        proxyServer.config.enableServer(serverId);
        
        // Notify clients about server changes
        io.emit('serverEnabled', { serverId });
        
        res.json({ success: true, message: 'Server enabled successfully' });
      } catch (error) {
        res.status(500).json({ error: 'Failed to enable server' });
      }
    });

    app.put('/mcp/config/servers/:serverId/disable', async (req, res) => {
      try {
        const { serverId } = req.params;
        proxyServer.config.disableServer(serverId);
        
        // Notify clients about server changes
        io.emit('serverDisabled', { serverId });
        
        res.json({ success: true, message: 'Server disabled successfully' });
      } catch (error) {
        res.status(500).json({ error: 'Failed to disable server' });
      }
    });

    // Streaming MCP endpoint for real-time communication
    app.post('/mcp/stream', (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Cache-Control'
      });

      const clientId = Math.random().toString(36).substr(2, 9);
      
      // Send initial connection message
      res.write(`data: ${JSON.stringify({ type: 'connected', clientId })}\n\n`);

      // Handle MCP protocol messages
      req.on('data', async (chunk) => {
        try {
          const message = JSON.parse(chunk.toString());
          
          // Process MCP message through proxy server
          const response = await this.processMcpMessage(message, proxyServer);
          
          // Send response back through stream
          res.write(`data: ${JSON.stringify(response)}\n\n`);
        } catch (error) {
          res.write(`data: ${JSON.stringify({ type: 'error', error: getErrorMessage(error) })}\n\n`);
        }
      });

      // Handle client disconnect
      req.on('close', () => {
        console.log(`Client ${clientId} disconnected`);
      });
    });
  }

  private setupOAuthRoutes(app: express.Application, proxyServer: ProxyMcpServer) {
    const oauthProvider = proxyServer.backend.getOAuthManager();
    
    // Enhanced CORS middleware for OAuth routes
    const oauthCorsMiddleware = (req: any, res: any, next: any) => {
      // Set comprehensive CORS headers
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Max-Age', '86400');
      
      // Handle preflight OPTIONS requests
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
      
      next();
    };
    
    // Apply CORS middleware to all OAuth routes
    app.use('/.well-known', oauthCorsMiddleware);
    app.use('/oauth', oauthCorsMiddleware);
    
    // OAuth metadata endpoint for the proxy server
    app.get('/.well-known/oauth-authorization-server', (req, res) => {
      res.json({
        issuer: `${req.protocol}://${req.get('host')}/oauth`,
        authorization_endpoint: `${req.protocol}://${req.get('host')}/oauth/authorize`,
        token_endpoint: `${req.protocol}://${req.get('host')}/oauth/token`,
        jwks_uri: `${req.protocol}://${req.get('host')}/oauth/jwks`,
        scopes_supported: ['read', 'write', 'admin'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        code_challenge_methods_supported: ['S256']
      });
    });
    
    // OAuth authorization endpoint - redirect to specific server OAuth
    app.get('/oauth/authorize', async (req, res) => {
      try {
        const { client_id, redirect_uri, scope, state, code_challenge, server_id } = req.query;
        
        // If server_id is specified, use that server's OAuth provider
        const serverId = server_id as string;
        if (serverId) {
          const serverInfo = oauthProvider.getOAuthServerInfo(serverId);
          if (!serverInfo) {
            return res.status(404).json({ error: 'OAuth server not found' });
          }
          
          // Get client information
          const client = await serverInfo.clientStore.get(client_id as string);
          if (!client) {
            return res.status(400).json({ error: 'Invalid client_id' });
          }
          
          // Prepare authorization parameters
          const authParams = {
            state: state as string,
            scopes: (scope as string)?.split(' ') || ['read'],
            codeChallenge: code_challenge as string,
            redirectUri: redirect_uri as string
          };
          
          // Delegate to server-specific OAuth provider
          await serverInfo.provider.authorize(client, authParams, res);
          return;
        }
        
        // Default OAuth server list if no specific server
        const oauthServers = oauthProvider.getAllOAuthServers();
        const serverList = oauthServers.map(server => ({
          serverId: server.serverId,
          serverName: server.config.name,
          authorizationUrl: `${req.protocol}://${req.get('host')}/oauth/authorize?server_id=${server.serverId}&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope || 'read'}&state=${state || ''}&code_challenge=${code_challenge || ''}`
        }));
        
        res.json({
          message: 'Multiple OAuth servers available',
          servers: serverList
        });
      } catch (error) {
        console.error('OAuth authorization error:', error);
        res.status(500).json({ 
          error: 'Authorization failed', 
          details: error instanceof Error ? error.message : String(error)
        });
      }
    });
    
    // OAuth token endpoint
    app.post('/oauth/token', async (req, res) => {
      try {
        const { grant_type, code, client_id, client_secret, redirect_uri, refresh_token, server_id } = req.body;
        
        // Find the appropriate OAuth server
        const serverId = server_id;
        if (!serverId) {
          return res.status(400).json({ error: 'server_id required' });
        }
        
        const serverInfo = oauthProvider.getOAuthServerInfo(serverId);
        if (!serverInfo) {
          return res.status(404).json({ error: 'OAuth server not found' });
        }
        
        // Get client information
        const client = await serverInfo.clientStore.get(client_id);
        if (!client) {
          return res.status(400).json({ error: 'Invalid client_id' });
        }
        
        let tokens;
        
        if (grant_type === 'authorization_code') {
          tokens = await serverInfo.provider.exchangeAuthorizationCode(
            client, 
            code, 
            undefined, // code_verifier
            redirect_uri
          );
        } else if (grant_type === 'refresh_token') {
          tokens = await serverInfo.provider.exchangeRefreshToken(
            client, 
            refresh_token
          );
        } else {
          return res.status(400).json({ error: 'Unsupported grant_type' });
        }
        
        res.json(tokens);
      } catch (error) {
        console.error('OAuth token error:', error);
        res.status(500).json({ 
          error: 'Token exchange failed', 
          details: error instanceof Error ? error.message : String(error)
        });
      }
    });
    
    // OAuth server information endpoint
    app.get('/mcp/oauth/servers', (req, res) => {
      try {
        const oauthServers = oauthProvider.getAllOAuthServers();
        res.json({ 
          servers: oauthServers.map(server => ({
            serverId: server.serverId,
            serverName: server.config.name,
            authorizationUrl: `${req.protocol}://${req.get('host')}/oauth/authorize?server_id=${server.serverId}`,
            tokenUrl: `${req.protocol}://${req.get('host')}/oauth/token`,
            configured: true
          }))
        });
      } catch (error) {
        res.status(500).json({ error: 'Failed to get OAuth server information' });
      }
    });
    
    // OAuth authorization URL endpoint for specific server
    app.get('/mcp/oauth/:serverId/authorize', (req, res) => {
      try {
        const { serverId } = req.params;
        const { redirect_uri, scopes } = req.query;
        
        const serverInfo = oauthProvider.getOAuthServerInfo(serverId);
        if (!serverInfo) {
          return res.status(404).json({ error: 'Server not found or OAuth not configured' });
        }
        
        const redirectUri = redirect_uri as string || `${req.protocol}://${req.get('host')}/oauth/callback`;
        const scopeList = typeof scopes === 'string' ? scopes.split(',') : ['read'];
        
        const authUrl = `${req.protocol}://${req.get('host')}/oauth/authorize?server_id=${serverId}&client_id=${serverInfo.serverId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scopeList.join(' ')}&response_type=code`;
        
        res.json({ authorizationUrl: authUrl });
      } catch (error) {
        res.status(500).json({ error: 'Failed to get authorization URL' });
      }
    });
  }

  private setupSocketHandlers(io: SocketIOServer, proxyServer: ProxyMcpServer) {
    io.on('connection', (socket) => {
      console.log('Client connected:', socket.id);

      // MCP tool call through WebSocket
      socket.on('mcp:callTool', async (data) => {
        try {
          const { toolName, arguments: args } = data;
          const [serverId, actualToolName] = toolName.split('__');
          
          const result = await proxyServer.backend.callTool(serverId, actualToolName, args);
          socket.emit('mcp:toolResult', { success: true, result });
        } catch (error) {
          socket.emit('mcp:toolResult', { success: false, error: getErrorMessage(error) });
        }
      });

      // Server status updates
      socket.on('mcp:getServerStatus', () => {
        const status = proxyServer.backend.getServerStatuses();
        socket.emit('mcp:serverStatus', status);
      });

      socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
      });
    });
  }

  private async processMcpMessage(message: any, proxyServer: ProxyMcpServer): Promise<any> {
    switch (message.method) {
      case 'tools/list':
        // Implementation would depend on your specific MCP server structure
        return { id: message.id, result: { tools: [] } };
      
      case 'tools/call':
        const { name, arguments: args } = message.params;
        const [serverId, toolName] = name.split('__');
        const result = await proxyServer.backend.callTool(serverId, toolName, args);
        return { id: message.id, result };
      
      default:
        throw new Error(`Unknown method: ${message.method}`);
    }
  }

  async start(): Promise<void> {
    if (!this.httpServer) {
      await this.initialize();
    }
    
    return new Promise((resolve) => {
      this.httpServer!.server.listen(this.port, () => {
        console.log(`🚀 MCP HTTP Server running on port ${this.port}`);
        console.log(`📡 Health check: http://localhost:${this.port}/health`);
        console.log(`🔌 WebSocket endpoint: ws://localhost:${this.port}`);
        console.log(`📊 MCP API: http://localhost:${this.port}/mcp/*`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (!this.httpServer) {
      return;
    }
    
    return new Promise((resolve) => {
      this.httpServer!.server.close(() => {
        console.log('MCP HTTP Server stopped');
        resolve();
      });
    });
  }

  getExpressApp(): express.Application | undefined {
    return this.httpServer?.app;
  }
}

// CLI usage
async function main() {
  const port = parseInt(process.env.MCP_HTTP_PORT || '3001');
  const server = new McpHttpServerManager(port);
  
  // Initialize and start the server
  console.error("🚀 Starting MCP HTTP Server initialization...");
  await server.start();

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('Shutting down MCP HTTP Server...');
    await server.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('Shutting down MCP HTTP Server...');
    await server.stop();
    process.exit(0);
  });
}

// Check if this file is being run directly
if (require.main === module) {
  main().catch(console.error);
}

export default McpHttpServerManager;
