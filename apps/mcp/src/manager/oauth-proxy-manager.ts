import { RequestHandler } from "express";
import { 
  mcpAuthRouter, 
  mcpAuthMetadataRouter,
  AuthRouterOptions,
  AuthMetadataOptions 
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { ProxyOAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { BackendServerConfig } from "../types.js";

export interface OAuthServerInfo {
  serverId: string;
  config: BackendServerConfig;
  authorizationUrl: string;
  tokenUrl: string;
  revocationUrl?: string;
  metadataUrl?: string;
  needsOAuth: boolean;
  oauthDetected: boolean;
  lastOAuthError?: string;
}

export class OAuthProxyManager {
  private oauthServers: Map<string, OAuthServerInfo> = new Map();
  private oauthProviders: Map<string, ProxyOAuthServerProvider> = new Map();
  private _router?: RequestHandler;

  constructor(private baseUrl: string = 'http://localhost:3000') {
    this.initializeOAuthDetection();
  }

  /**
   * Initialize OAuth detection for all servers
   */
  private initializeOAuthDetection() {
    console.error("🔐 Initializing OAuth detection system...");
  }

  /**
   * Force OAuth detection for all configured servers
   */
  async forceOAuthDetection(serverConfigs: any[]): Promise<void> {
    console.error("🔍 Force checking OAuth requirements for all servers...");
    
    for (const config of serverConfigs) {
      if (config.enabled && this.isGitHubMcpServer(config)) {
        console.error(`🔐 Force enabling OAuth for GitHub server: ${config.id}`);
        await this.detectOAuthRequirement(config.id, config, "Force OAuth detection for GitHub MCP server");
      }
    }
  }

  /**
   * Detect if a server needs OAuth authentication
   */
  async detectOAuthRequirement(serverId: string, config: BackendServerConfig, error?: string): Promise<boolean> {
    const existingInfo = this.oauthServers.get(serverId);
    
    // Check for OAuth indicators in error messages
    const needsOAuth = this.isOAuthError(error) || await this.checkOAuthMetadata(config);
    
    if (needsOAuth) {
      const oauthInfo: OAuthServerInfo = {
        serverId,
        config,
        authorizationUrl: this.buildOAuthUrl(config, '/oauth/authorize'),
        tokenUrl: this.buildOAuthUrl(config, '/oauth/token'),
        revocationUrl: this.buildOAuthUrl(config, '/oauth/revoke'),
        metadataUrl: this.buildOAuthUrl(config, '/.well-known/oauth-authorization-server'),
        needsOAuth: true,
        oauthDetected: true,
        lastOAuthError: error,
        ...existingInfo
      };
      
      this.oauthServers.set(serverId, oauthInfo);
      await this.setupOAuthProxy(oauthInfo);
      
      console.error(`🔐 OAuth detected for server ${serverId}: ${config.name}`);
      return true;
    }
    
    return false;
  }

  /**
   * Check if an error indicates OAuth is needed
   */
  private isOAuthError(error?: string): boolean {
    if (!error) return false;
    
    const oauthIndicators = [
      'authorization',
      'unauthorized',
      '401',
      'access_token',
      'oauth',
      'bearer',
      'authentication required',
      'missing required authorization header',
      'invalid_token',
      'token_expired'
    ];
    
    const errorLower = error.toLowerCase();
    return oauthIndicators.some(indicator => errorLower.includes(indicator));
  }

  /**
   * Check if server has OAuth metadata endpoints
   */
  private async checkOAuthMetadata(config: BackendServerConfig): Promise<boolean> {
    if (config.transportType !== 'http' && config.transportType !== 'sse') {
      return false;
    }
    
    // GitHub MCP server always supports OAuth
    if (this.isGitHubMcpServer(config)) {
      console.error(`🔐 GitHub MCP server detected - OAuth support enabled`);
      return true;
    }
    
    try {
      const baseUrl = config.http?.url || config.sse?.url;
      if (!baseUrl) return false;
      
      const metadataUrl = this.buildOAuthUrl(config, '/.well-known/oauth-authorization-server');
      const response = await fetch(metadataUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.ok) {
        const metadata = await response.json();
        return metadata.authorization_endpoint && metadata.token_endpoint;
      }
    } catch (error) {
      // Metadata check failed, not necessarily an OAuth server
      console.error(`OAuth metadata check failed for ${config.id}:`, error);
    }
    
    return false;
  }

  /**
   * Build OAuth URL based on server config
   */
  private buildOAuthUrl(config: BackendServerConfig, path: string): string {
    const baseUrl = config.http?.url || config.sse?.url || '';
    if (!baseUrl) return '';
    
    // Special handling for GitHub MCP Server
    if (this.isGitHubMcpServer(config)) {
      return this.getGitHubOAuthUrl(path);
    }
    
    try {
      const url = new URL(baseUrl);
      url.pathname = path;
      return url.toString();
    } catch {
      return baseUrl + path;
    }
  }

  /**
   * Check if this is the GitHub MCP server
   */
  private isGitHubMcpServer(config: BackendServerConfig): boolean {
    const baseUrl = config.http?.url || config.sse?.url || '';
    return baseUrl.includes('githubcopilot.com') || 
           baseUrl.includes('github.com') ||
           config.id === 'github' ||
           config.name?.toLowerCase().includes('github');
  }

  /**
   * Get correct GitHub OAuth URLs
   */
  private getGitHubOAuthUrl(path: string): string {
    const pathMap: Record<string, string> = {
      '/oauth/authorize': 'https://github.com/login/oauth/authorize',
      '/oauth/token': 'https://github.com/login/oauth/access_token',
      '/oauth/revoke': 'https://github.com/login/oauth/revoke',
      '/.well-known/oauth-authorization-server': 'https://github.com/.well-known/oauth-authorization-server'
    };
    
    return pathMap[path] || `https://github.com${path}`;
  }

  /**
   * Set up OAuth proxy for a specific server
   */
  private async setupOAuthProxy(oauthInfo: OAuthServerInfo): Promise<void> {
    try {
      const proxyProvider = new ProxyOAuthServerProvider({
        endpoints: {
          authorizationUrl: oauthInfo.authorizationUrl,
          tokenUrl: oauthInfo.tokenUrl,
          revocationUrl: oauthInfo.revocationUrl,
        },
        verifyAccessToken: async (token: string): Promise<AuthInfo> => {
          // For GitHub MCP server, create AuthInfo with GitHub token
          if (this.isGitHubMcpServer(oauthInfo.config)) {
            return {
              token,
              clientId: 'github-mcp-client',
              scopes: ['repo', 'read:user', 'read:org'],
              extra: { 
                serverId: oauthInfo.serverId,
                provider: 'github'
              }
            };
          }
          
          // For other servers, create basic AuthInfo
          return {
            token,
            clientId: 'mcp-proxy',
            scopes: ['read', 'write'],
            extra: { serverId: oauthInfo.serverId }
          };
        },
        getClient: async (clientId: string): Promise<OAuthClientInformationFull | undefined> => {
          // Return GitHub-specific client info for GitHub MCP server
          if (this.isGitHubMcpServer(oauthInfo.config)) {
            return {
              client_id: 'github-mcp-client',
              client_name: 'GitHub MCP Client',
              redirect_uris: [`${this.baseUrl}/oauth/callback`],
              grant_types: ['authorization_code', 'refresh_token'],
              response_types: ['code'],
              token_endpoint_auth_method: 'client_secret_basic'
            };
          }
          
          // Return basic client info for other servers
          return {
            client_id: clientId,
            client_name: `MCP Proxy Client for ${oauthInfo.serverId}`,
            redirect_uris: [`${this.baseUrl}/oauth/callback`],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic'
          };
        }
      });
      
      this.oauthProviders.set(oauthInfo.serverId, proxyProvider);
      console.error(`🔗 OAuth proxy configured for ${oauthInfo.serverId}`);
    } catch (error) {
      console.error(`❌ Failed to setup OAuth proxy for ${oauthInfo.serverId}:`, error);
    }
  }

  /**
   * Get OAuth router for Express app
   */
  getOAuthRouter(): RequestHandler {
    if (this._router) return this._router;
    
    // Create a custom router that handles OAuth for multiple servers, especially GitHub
    this._router = (req, res, next) => {
      // Handle CORS preflight requests
      if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
        res.header('Access-Control-Max-Age', '86400');
        return res.sendStatus(200);
      }
      
      // Add CORS headers to all responses
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
      
      // Check if this is a GitHub OAuth request and proxy to GitHub
      if (req.path.includes('authorize') || req.path.includes('token')) {
        // Find GitHub server in OAuth servers
        const githubServer = Array.from(this.oauthServers.values()).find(server => 
          this.isGitHubMcpServer(server.config)
        );
        
        if (githubServer) {
          return this.handleGitHubOAuthRequest(req, res, githubServer);
        }
      }
      
      // For non-GitHub OAuth or other requests, use the standard MCP OAuth router
      const firstProvider = Array.from(this.oauthProviders.values())[0];
      
      if (!firstProvider) {
        return res.status(404).json({ error: 'No OAuth providers configured' });
      }
      
      const routerOptions: AuthRouterOptions = {
        provider: firstProvider,
        issuerUrl: new URL(`${this.baseUrl}/oauth`),
        baseUrl: new URL(this.baseUrl),
        scopesSupported: ['read', 'write', 'admin'],
        resourceName: 'MCP Proxy Server'
      };
      
      const mcpRouter = mcpAuthRouter(routerOptions);
      mcpRouter(req, res, next);
    };
    
    return this._router;
  }

  /**
   * Handle GitHub OAuth requests by proxying to actual GitHub OAuth endpoints
   */
  private handleGitHubOAuthRequest(req: any, res: any, githubServer: OAuthServerInfo): void {
    try {
      let targetUrl: string;
      
      if (req.path.includes('authorize')) {
        // Proxy authorization requests to GitHub
        targetUrl = 'https://github.com/login/oauth/authorize';
        if (req.query) {
          const queryString = new URLSearchParams(req.query as Record<string, string>).toString();
          targetUrl += `?${queryString}`;
        }
      } else if (req.path.includes('token')) {
        // Proxy token requests to GitHub
        targetUrl = 'https://github.com/login/oauth/access_token';
      } else {
        return res.status(404).json({ error: 'Unknown OAuth endpoint' });
      }
      
      // For authorization requests, redirect to GitHub
      if (req.path.includes('authorize')) {
        return res.redirect(targetUrl);
      }
      
      // For token requests, we would need to proxy the POST request
      // This is a simplified implementation - in production, you'd want proper token handling
      res.json({ 
        authorization_url: githubServer.authorizationUrl,
        token_url: githubServer.tokenUrl,
        message: 'Use the authorization_url to start OAuth flow'
      });
      
    } catch (error) {
      console.error('Error handling GitHub OAuth request:', error);
      res.status(500).json({ error: 'OAuth request failed' });
    }
  }

  /**
   * Get OAuth metadata router
   */
  getOAuthMetadataRouter(): RequestHandler {
    return (req, res, next) => {
      // Handle CORS preflight requests
      if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
        res.header('Access-Control-Max-Age', '86400');
        return res.sendStatus(200);
      }
      
      // Add CORS headers to all responses
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
      
      const oauthMetadata: OAuthMetadata = {
        issuer: `${this.baseUrl}/oauth`,
        authorization_endpoint: `${this.baseUrl}/oauth/authorize`,
        token_endpoint: `${this.baseUrl}/oauth/token`,
        jwks_uri: `${this.baseUrl}/oauth/jwks`,
        scopes_supported: ['read', 'write', 'admin'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        code_challenge_methods_supported: ['S256']
      };
      
      const metadataOptions: AuthMetadataOptions = {
        oauthMetadata,
        resourceServerUrl: new URL(this.baseUrl),
        scopesSupported: ['read', 'write', 'admin'],
        resourceName: 'MCP Proxy Server'
      };
      
      const metadataRouter = mcpAuthMetadataRouter(metadataOptions);
      metadataRouter(req, res, next);
    };
  }

  /**
   * Get all servers that need OAuth
   */
  getOAuthServers(): OAuthServerInfo[] {
    return Array.from(this.oauthServers.values());
  }

  /**
   * Get OAuth server info by ID
   */
  getOAuthServerInfo(serverId: string): OAuthServerInfo | undefined {
    return this.oauthServers.get(serverId);
  }

  /**
   * Check if a server needs OAuth authentication
   */
  serverNeedsOAuth(serverId: string): boolean {
    const info = this.oauthServers.get(serverId);
    return info?.needsOAuth || false;
  }

  /**
   * Get authorization URL for a server
   */
  getAuthorizationUrl(serverId: string, redirectUri: string, scopes: string[] = ['read']): string | undefined {
    const info = this.oauthServers.get(serverId);
    if (!info) return undefined;
    
    const url = new URL(info.authorizationUrl);
    url.searchParams.set('client_id', 'mcp-proxy');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', scopes.join(' '));
    url.searchParams.set('state', `server:${serverId}`);
    
    return url.toString();
  }

  /**
   * Remove OAuth configuration for a server
   */
  removeOAuthServer(serverId: string): void {
    this.oauthServers.delete(serverId);
    this.oauthProviders.delete(serverId);
    this._router = undefined; // Force router recreation
  }

  /**
   * Get OAuth diagnostics
   */
  getOAuthDiagnostics() {
    const servers = Array.from(this.oauthServers.values());
    
    return {
      totalServers: servers.length,
      needsOAuth: servers.filter(s => s.needsOAuth).length,
      configured: servers.filter(s => this.oauthProviders.has(s.serverId)).length,
      errors: servers.filter(s => s.lastOAuthError).length,
      servers: servers.map(server => ({
        serverId: server.serverId,
        serverName: server.config.name,
        needsOAuth: server.needsOAuth,
        oauthDetected: server.oauthDetected,
        configured: this.oauthProviders.has(server.serverId),
        authorizationUrl: server.authorizationUrl,
        tokenUrl: server.tokenUrl,
        lastError: server.lastOAuthError
      }))
    };
  }
}