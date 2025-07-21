// BackendServerManager handles connections to multiple MCP servers as clients
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  BackendServerConfig,
  BackendServerStatus,
  ProxyToolDefinition,
  AuthInfo,
} from "../types.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";

export interface BackendServerConnection {
  config: BackendServerConfig;
  client: Client;
  transport: any;
  status: BackendServerStatus;
  tools: Map<string, any>;
  resources: Map<string, any>;
  prompts: Map<string, any>;
}

export class BackendServerManager {
  private connections: Map<string, BackendServerConnection> = new Map();
  private reconnectIntervals: Map<string, NodeJS.Timeout> = new Map();
  private _initialized: Promise<void>;

  constructor(private serverConfigs: BackendServerConfig[]) {
    this._initialized = this.initializeServers();
  }

  // Helper function to substitute environment variables in strings
  private substituteEnvVars(value: string): string {
    return value.replace(/\$\{([^}]+)\}/g, (match, envVar) => {
      return process.env[envVar] || match;
    });
  }

  // Helper function to substitute environment variables in headers object
  private substituteEnvVarsInHeaders(headers: Record<string, string>): Record<string, string> {
    const substituted: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      substituted[key] = this.substituteEnvVars(value);
    }
    return substituted;
  }

  // Wait for all initial connections to complete
  async waitForInitialization(): Promise<void> {
    await this._initialized;
  }

  private async initializeServers() {
    console.error(`Initializing ${this.serverConfigs.length} backend servers...`);
    for (const config of this.serverConfigs) {
      if (config.enabled) {
        console.error(`Connecting to server: ${config.id} (${config.name})`);
        await this.connectToServer(config);
      } else {
        console.error(`Skipping disabled server: ${config.id} (${config.name})`);
      }
    }
    console.error(`Backend server initialization complete. ${this.connections.size} servers connected.`);
  }

  async connectToServer(config: BackendServerConfig): Promise<void> {
    try {
      const client = new Client(
        {
          name: `proxy-client-${config.id}`,
          version: "1.0.0",
        },
        {
          capabilities: {
            roots: {},
            sampling: {},
          },
        }
      );

      let transport;
      switch (config.transportType) {
        case "stdio":
          if (!config.stdio) {
            throw new Error("stdio configuration required for stdio transport");
          }
          transport = new StdioClientTransport({
            command: config.stdio.command,
            args: config.stdio.args || [],
            env: config.stdio.env,
          });
          break;
        case "http":
          if (!config.http) {
            throw new Error("http configuration required for http transport");
          }
          const httpOptions: any = {};
          if (config.http.headers) {
            httpOptions.headers = this.substituteEnvVarsInHeaders(config.http.headers);
          }
          if (config.http.timeout) {
            httpOptions.timeout = config.http.timeout;
          }
          transport = new StreamableHTTPClientTransport(new URL(config.http.url), httpOptions);
          break;
        case "sse":
          if (!config.sse) {
            throw new Error("sse configuration required for sse transport");
          }
          transport = new SSEClientTransport(new URL(config.sse.url));
          break;
        default:
          throw new Error(`Unsupported transport type: ${config.transportType}`);
      }

      await client.connect(transport);

      const connection: BackendServerConnection = {
        config,
        client,
        transport,
        status: {
          id: config.id,
          connected: true,
          lastConnected: new Date(),
          toolsCount: 0,
          resourcesCount: 0,
          promptsCount: 0,
        },
        tools: new Map(),
        resources: new Map(),
        prompts: new Map(),
      };

      // Load available capabilities
      await this.loadServerCapabilities(connection);

      this.connections.set(config.id, connection);
      console.error(`Connected to backend server: ${config.name} (${config.id})`);
    } catch (error) {
      console.error(`Failed to connect to server ${config.id}:`, error);
      const status: BackendServerStatus = {
        id: config.id,
        connected: false,
        lastError: error instanceof Error ? error.message : String(error),
      };
      this.scheduleReconnect(config);
    }
  }

  private async loadServerCapabilities(connection: BackendServerConnection) {
    try {
      console.error(`Loading capabilities for server: ${connection.config.id}`);
      
      // Load tools
      const toolsResult = await connection.client.listTools();
      if (toolsResult.tools) {
        connection.tools.clear();
        for (const tool of toolsResult.tools) {
          connection.tools.set(tool.name, tool);
        }
        connection.status.toolsCount = toolsResult.tools.length;
        console.error(`Loaded ${toolsResult.tools.length} tools for server ${connection.config.id}: ${toolsResult.tools.map(t => t.name).join(', ')}`);
      } else {
        console.error(`No tools found for server ${connection.config.id}`);
      }

      // Load resources
      try {
        const resourcesResult = await connection.client.listResources();
        if (resourcesResult.resources) {
          connection.resources.clear();
          for (const resource of resourcesResult.resources) {
            connection.resources.set(resource.uri, resource);
          }
          connection.status.resourcesCount = resourcesResult.resources.length;
          console.error(`Loaded ${resourcesResult.resources.length} resources for server ${connection.config.id}`);
        }
      } catch (error) {
        // Resources not supported
      }

      // Load prompts
      try {
        const promptsResult = await connection.client.listPrompts();
        if (promptsResult.prompts) {
          connection.prompts.clear();
          for (const prompt of promptsResult.prompts) {
            connection.prompts.set(prompt.name, prompt);
          }
          connection.status.promptsCount = promptsResult.prompts.length;
        }
      } catch (error) {
        // Prompts not supported
      }
    } catch (error) {
      console.error(`Failed to load capabilities for server ${connection.config.id}:`, error);
    }
  }

  private scheduleReconnect(config: BackendServerConfig) {
    if (this.reconnectIntervals.has(config.id)) {
      return;
    }

    const interval = setInterval(async () => {
      try {
        await this.connectToServer(config);
        clearInterval(interval);
        this.reconnectIntervals.delete(config.id);
      } catch (error) {
        console.log(`Reconnection attempt failed for ${config.id}, will retry...`);
      }
    }, 30000); // Retry every 30 seconds

    this.reconnectIntervals.set(config.id, interval);
  }

  async disconnectServer(serverId: string): Promise<void> {
    const connection = this.connections.get(serverId);
    if (connection) {
      try {
        await connection.client.close();
      } catch (error) {
        console.error(`Error closing connection to ${serverId}:`, error);
      }
      this.connections.delete(serverId);
    }

    const interval = this.reconnectIntervals.get(serverId);
    if (interval) {
      clearInterval(interval);
      this.reconnectIntervals.delete(serverId);
    }
  }

  getServerConnection(serverId: string): BackendServerConnection | undefined {
    return this.connections.get(serverId);
  }

  getAllConnections(): BackendServerConnection[] {
    return Array.from(this.connections.values());
  }

  getConnectedServers(): BackendServerConnection[] {
    return Array.from(this.connections.values()).filter(conn => conn.status.connected);
  }

  getServerStatuses(): BackendServerStatus[] {
    return Array.from(this.connections.values()).map(conn => conn.status);
  }

  async callTool(
    serverId: string,
    toolName: string,
    args: Record<string, unknown>,
    authInfo?: AuthInfo
  ): Promise<any> {
    const connection = this.connections.get(serverId);
    if (!connection) {
      throw new McpError(ErrorCode.InvalidRequest, `Server ${serverId} not found`);
    }

    if (!connection.status.connected) {
      throw new McpError(ErrorCode.InvalidRequest, `Server ${serverId} not connected`);
    }

    // Check security permissions
    if (!this.isToolAllowed(connection.config, toolName, authInfo)) {
      throw new McpError(ErrorCode.InvalidRequest, `Tool ${toolName} not allowed for server ${serverId}`);
    }

    try {
      return await connection.client.callTool({ name: toolName, arguments: args });
    } catch (error) {
      console.error(`Error calling tool ${toolName} on server ${serverId}:`, error);
      throw error;
    }
  }

  private isToolAllowed(
    config: BackendServerConfig,
    toolName: string,
    authInfo?: AuthInfo
  ): boolean {
    const security = config.security;
    if (!security) return true;

    // Check blocked tools
    if (security.blockedTools?.includes(toolName)) {
      return false;
    }

    // Check allowed tools (if specified)
    if (security.allowedTools && !security.allowedTools.includes(toolName)) {
      return false;
    }

    // Check auth requirements
    if (security.requireAuth && !authInfo) {
      return false;
    }

    // Check scopes
    if (security.allowedScopes && authInfo) {
      const hasRequiredScope = security.allowedScopes.some(scope =>
        authInfo.scopes.includes(scope)
      );
      if (!hasRequiredScope) {
        return false;
      }
    }

    return true;
  }

  async addServer(config: BackendServerConfig): Promise<void> {
    this.serverConfigs.push(config);
    if (config.enabled) {
      await this.connectToServer(config);
    }
  }

  async removeServer(serverId: string): Promise<void> {
    await this.disconnectServer(serverId);
    this.serverConfigs = this.serverConfigs.filter(config => config.id !== serverId);
  }

  async enableServer(serverId: string): Promise<void> {
    const config = this.serverConfigs.find(c => c.id === serverId);
    if (config) {
      config.enabled = true;
      await this.connectToServer(config);
    }
  }

  async disableServer(serverId: string): Promise<void> {
    const config = this.serverConfigs.find(c => c.id === serverId);
    if (config) {
      config.enabled = false;
      await this.disconnectServer(serverId);
    }
  }

  async refreshServerCapabilities(serverId: string): Promise<void> {
    const connection = this.connections.get(serverId);
    if (connection && connection.status.connected) {
      await this.loadServerCapabilities(connection);
    }
  }

  async shutdown(): Promise<void> {
    // Clear all reconnect intervals
    for (const interval of this.reconnectIntervals.values()) {
      clearInterval(interval);
    }
    this.reconnectIntervals.clear();

    // Disconnect all servers
    const disconnectPromises = Array.from(this.connections.keys()).map(serverId =>
      this.disconnectServer(serverId)
    );
    await Promise.all(disconnectPromises);
  }
}
