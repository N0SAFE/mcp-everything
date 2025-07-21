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
import { OAuthProxyManager } from "./oauth-proxy-manager.js";

export interface BackendServerConnection {
  config: BackendServerConfig;
  client: Client;
  transport: any;
  status: BackendServerStatus;
  tools: Map<string, any>;
  resources: Map<string, any>;
  prompts: Map<string, any>;
}

export interface FailedServerAttempt {
  config: BackendServerConfig;
  status: BackendServerStatus;
  attemptCount: number;
  firstFailure: Date;
  lastAttempt: Date;
}

export class BackendServerManager {
  private connections: Map<string, BackendServerConnection> = new Map();
  private failedServers: Map<string, FailedServerAttempt> = new Map();
  private reconnectIntervals: Map<string, NodeJS.Timeout> = new Map();
  private _initialized: Promise<void>;
  private oauthManager: OAuthProxyManager;

  constructor(private serverConfigs: BackendServerConfig[]) {
    this.oauthManager = new OAuthProxyManager();
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
      
      // Remove from failed servers if it was there
      this.failedServers.delete(config.id);
      
      console.error(`Connected to backend server: ${config.name} (${config.id})`);
    } catch (error) {
      console.error(`Failed to connect to server ${config.id}:`, error);
      
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Check if this is an OAuth-related error
      const needsOAuth = await this.oauthManager.detectOAuthRequirement(config.id, config, errorMessage);
      
      if (needsOAuth) {
        console.error(`🔐 OAuth requirement detected for server ${config.id}`);
      }
      
      // Track failed server attempt
      const existingFailure = this.failedServers.get(config.id);
      const now = new Date();
      
      if (existingFailure) {
        // Update existing failure record
        existingFailure.attemptCount++;
        existingFailure.lastAttempt = now;
        existingFailure.status.lastError = errorMessage;
      } else {
        // Create new failure record
        const failedAttempt: FailedServerAttempt = {
          config,
          status: {
            id: config.id,
            connected: false,
            lastError: errorMessage,
          },
          attemptCount: 1,
          firstFailure: now,
          lastAttempt: now,
        };
        this.failedServers.set(config.id, failedAttempt);
      }
      
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

    // Also remove from failed servers
    this.failedServers.delete(serverId);

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

  getFailedServers(): FailedServerAttempt[] {
    return Array.from(this.failedServers.values());
  }

  getAllServerStatuses(): Array<BackendServerConnection | FailedServerAttempt> {
    const connected = Array.from(this.connections.values());
    const failed = Array.from(this.failedServers.values());
    const disabled = this.serverConfigs
      .filter(config => !config.enabled && !this.connections.has(config.id) && !this.failedServers.has(config.id))
      .map(config => ({
        config,
        status: {
          id: config.id,
          connected: false,
          lastError: 'Server disabled',
        },
        attemptCount: 0,
        firstFailure: new Date(),
        lastAttempt: new Date(),
      } as FailedServerAttempt));
    
    return [...connected, ...failed, ...disabled];
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

  /**
   * Get the OAuth proxy manager
   */
  getOAuthManager(): OAuthProxyManager {
    return this.oauthManager;
  }

  /**
   * Get servers that need OAuth authentication
   */
  getOAuthServers() {
    return this.oauthManager.getOAuthServers();
  }

  /**
   * Check if a server needs OAuth
   */
  serverNeedsOAuth(serverId: string): boolean {
    return this.oauthManager.serverNeedsOAuth(serverId);
  }

  /**
   * Get OAuth authorization URL for a server
   */
  getOAuthAuthorizationUrl(serverId: string, redirectUri: string, scopes?: string[]): string | undefined {
    return this.oauthManager.getAuthorizationUrl(serverId, redirectUri, scopes);
  }
}
