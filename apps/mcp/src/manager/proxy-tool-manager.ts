// ProxyToolManager creates and manages proxy tools that forward calls to backend servers
import { ToolManager } from "./tool-manager.js";
import { BackendServerManager } from "./backend-server-manager.js";
import {
  ToolDefinition,
  ToolCapability,
  ProxyToolDefinition,
  AuthInfo,
  ToolsetConfig,
  DynamicToolDiscoveryOptions,
} from "../types.js";
import { createTool, createToolDefinition } from "../utils/tools.js";

// Check if debug logging is enabled
const DEBUG_ENABLED = process.env.MCP_DEBUG === "true" || process.env.NODE_ENV === "development";

// Debug logging function that only outputs when debug is enabled
function debugLog(...args: any[]) {
  if (DEBUG_ENABLED) {
    console.error(...args);
  }
}
import { z } from "zod";

export class ProxyToolManager extends ToolManager {
  private backendServerManager: BackendServerManager;
  private serverDiscoveryTools: ToolCapability[] = [];
  private _initializationComplete: Promise<void>;

  constructor(
    mcpServerName: string,
    backendServerManager: BackendServerManager,
    toolsetConfig: ToolsetConfig,
    dynamicToolDiscovery?: DynamicToolDiscoveryOptions
  ) {
    // Initialize with server discovery tools
    const discoveryTools = ProxyToolManager.createServerDiscoveryTools(
      mcpServerName,
      backendServerManager
    );

    super(mcpServerName, discoveryTools, toolsetConfig, dynamicToolDiscovery);
    this.backendServerManager = backendServerManager;
    this.serverDiscoveryTools = discoveryTools;

    // Start proxy tools initialization
    this._initializationComplete = this.initializeProxyTools();

    // Set up auto-refresh when servers change
    this.setupServerChangeHandlers();
  }

  // Wait for proxy tool initialization to complete
  async waitForInitialization(): Promise<void> {
    await this._initializationComplete;
  }

  private async initializeProxyTools() {
    // Wait for backend servers to initialize
    await this.backendServerManager.waitForInitialization();
    
    // Now load proxy tools from connected servers
    await this.loadProxyToolsFromServers();
    
    // Notify about tool list changes
    this.notifyEnabledToolsChanged();
  }

  private static createServerDiscoveryTools(
    mcpServerName: string,
    backendServerManager: BackendServerManager
  ): ToolCapability[] {
    const serverListTool = createToolDefinition({
      name: "proxy_server_list",
      description: "List all configured backend MCP servers and their status",
      inputSchema: z.object({
        includeDisabled: z.boolean().optional().describe("Include disabled servers in the list"),
        includeDetails: z.boolean().optional().describe("Include detailed server information"),
      }),
      annotations: {
        title: "List Backend Servers",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    });

    const serverToolsTool = createToolDefinition({
      name: "proxy_server_tools",
      description: "List all tools available from a specific backend server",
      inputSchema: z.object({
        serverId: z.string().describe("ID of the backend server"),
        includeDisabled: z.boolean().optional().describe("Include disabled tools"),
      }),
      annotations: {
        title: "List Server Tools",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    });

    const serverStatusTool = createToolDefinition({
      name: "proxy_server_status",
      description: "Get detailed status information for backend servers",
      inputSchema: z.object({
        serverId: z.string().optional().describe("Specific server ID (if not provided, shows all)"),
      }),
      annotations: {
        title: "Server Status",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    });

    const refreshServerTool = createToolDefinition({
      name: "proxy_server_refresh",
      description: "Refresh capabilities for a specific backend server",
      inputSchema: z.object({
        serverId: z.string().describe("ID of the backend server to refresh"),
      }),
      annotations: {
        title: "Refresh Server",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    });

    return [
      createTool(serverListTool, async (params) => {
        const allServers = params.includeDisabled 
          ? backendServerManager.getAllServerStatuses()
          : backendServerManager.getAllConnections();

        const servers = allServers.map(serverOrConnection => {
          // Handle both BackendServerConnection and FailedServerAttempt
          const isConnection = 'client' in serverOrConnection;
          const config = serverOrConnection.config;
          const status = serverOrConnection.status;
          
          const basic = {
            id: config.id,
            name: config.name,
            description: config.description,
            transportType: config.transportType,
            enabled: config.enabled,
            connected: status.connected,
            toolsCount: status.toolsCount || 0,
          };

          if (params.includeDetails) {
            const details = {
              ...basic,
              lastConnected: status.lastConnected,
              lastError: status.lastError,
              resourcesCount: status.resourcesCount || 0,
              promptsCount: status.promptsCount || 0,
              security: config.security,
            };

            // Add additional info for failed servers
            if (!isConnection && 'attemptCount' in serverOrConnection) {
              return {
                ...details,
                attemptCount: serverOrConnection.attemptCount,
                firstFailure: serverOrConnection.firstFailure,
                lastAttempt: serverOrConnection.lastAttempt,
              };
            }

            return details;
          }

          return basic;
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                servers,
                totalServers: servers.length,
                connectedServers: servers.filter(s => s.connected).length,
                disconnectedServers: servers.filter(s => !s.connected).length,
                enabledServers: servers.filter(s => s.enabled).length,
                disabledServers: servers.filter(s => !s.enabled).length,
              }, null, 2),
            },
          ],
        };
      }),

      createTool(serverToolsTool, async (params) => {
        const connection = backendServerManager.getServerConnection(params.serverId);
        if (!connection) {
          throw new Error(`Server ${params.serverId} not found`);
        }

        const tools = Array.from(connection.tools.values());
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                serverId: params.serverId,
                serverName: connection.config.name,
                connected: connection.status.connected,
                tools: tools.map(tool => ({
                  name: tool.name,
                  description: tool.description,
                  inputSchema: tool.inputSchema,
                })),
                totalTools: tools.length,
              }, null, 2),
            },
          ],
        };
      }),

      createTool(serverStatusTool, async (params) => {
        if (params.serverId) {
          const connection = backendServerManager.getServerConnection(params.serverId);
          if (!connection) {
            throw new Error(`Server ${params.serverId} not found`);
          }
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(connection.status, null, 2),
              },
            ],
          };
        } else {
          const statuses = backendServerManager.getServerStatuses();
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  servers: statuses,
                  summary: {
                    total: statuses.length,
                    connected: statuses.filter(s => s.connected).length,
                    disconnected: statuses.filter(s => !s.connected).length,
                  },
                }, null, 2),
              },
            ],
          };
        }
      }),

      createTool(refreshServerTool, async (params) => {
        await backendServerManager.refreshServerCapabilities(params.serverId);
        return {
          content: [
            {
              type: "text",
              text: `Server ${params.serverId} capabilities refreshed`,
            },
          ],
        };
      }),
    ];
  }
  
  hasTools() {return true}

  private async loadProxyToolsFromServers() {
    debugLog("Loading proxy tools from servers...");
    const connections = this.backendServerManager.getConnectedServers();
    debugLog(`Found ${connections.length} connected servers`);
    const proxyTools: ToolCapability[] = [];

    for (const connection of connections) {
      debugLog(`Loading tools from server: ${connection.config.id} (${connection.tools.size} tools)`);
      for (const [toolName, tool] of connection.tools) {
        // Create proxy tool
        const proxyToolName = `${connection.config.id}__${toolName}`;
        const proxyTool = this.createProxyTool(connection.config.id, tool, proxyToolName);
        proxyTools.push(proxyTool);
        debugLog(`Created proxy tool: ${proxyToolName}`);
      }
    }

    debugLog(`Total proxy tools created: ${proxyTools.length}`);

    // Add proxy tools to the manager
    for (const proxyTool of proxyTools) {
      this.tools.set(proxyTool.definition.name, proxyTool);
      
      // Enable the tool if it should be enabled by default
      if (this.toolsetConfig.mode === "readWrite" || 
          (proxyTool.definition.annotations?.readOnlyHint !== false)) {
        this.enabledTools.add(proxyTool.definition.name);
        debugLog(`Enabled proxy tool: ${proxyTool.definition.name}`);
      }
    }
    
    debugLog(`Total tools in manager: ${this.tools.size}`);
    debugLog(`Total enabled tools: ${this.enabledTools.size}`);
  }

  private createProxyTool(
    serverId: string,
    originalTool: ToolDefinition,
    proxyToolName: string
  ): ToolCapability {
    const proxyToolDefinition: ProxyToolDefinition = {
      name: proxyToolName,
      description: `[${serverId}] ${originalTool.description}`,
      inputSchema: originalTool.inputSchema,
      annotations: {
        ...originalTool.annotations,
        title: `${originalTool.annotations?.title || originalTool.name} (via ${serverId})`,
      },
      serverId,
      originalName: originalTool.name,
      proxyName: proxyToolName,
    };

    return createTool(proxyToolDefinition, async (params, req, opts) => {
      try {
        const result = await this.backendServerManager.callTool(
          serverId,
          originalTool.name,
          params,
          opts.authInfo
        );
        return result;
      } catch (error) {
        debugLog(`Error calling tool ${originalTool.name} on server ${serverId}:`, error);
        return {
          content: [
            {
              type: "text",
              text: `Error calling tool: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    });
  }

  private setupServerChangeHandlers() {
    // This would ideally be implemented with event listeners on the BackendServerManager
    // For now, we'll implement a polling mechanism to check for changes
    setInterval(() => {
      this.refreshProxyTools();
    }, 30000); // Check every 30 seconds
  }

  private async refreshProxyTools() {
    // Remove all proxy tools (keep discovery tools)
    const toolsToRemove: string[] = [];
    for (const [toolName, tool] of this.tools) {
      if (!this.serverDiscoveryTools.some(dt => dt.definition.name === toolName)) {
        toolsToRemove.push(toolName);
      }
    }

    for (const toolName of toolsToRemove) {
      this.tools.delete(toolName);
      this.enabledTools.delete(toolName);
    }

    // Reload proxy tools
    await this.loadProxyToolsFromServers();

    // Notify about tool list changes
    this.notifyEnabledToolsChanged();
  }

  async refreshServerTools(serverId: string) {
    // Remove tools for specific server
    const toolsToRemove: string[] = [];
    for (const [toolName, tool] of this.tools) {
      if ('serverId' in tool.definition && tool.definition.serverId === serverId) {
        toolsToRemove.push(toolName);
      }
    }

    for (const toolName of toolsToRemove) {
      this.tools.delete(toolName);
      this.enabledTools.delete(toolName);
    }

    // Reload tools for this server
    const connection = this.backendServerManager.getServerConnection(serverId);
    if (connection && connection.status.connected) {
      for (const [toolName, tool] of connection.tools) {
        const proxyToolName = `${serverId}__${toolName}`;
        const proxyTool = this.createProxyTool(serverId, tool, proxyToolName);
        this.tools.set(proxyTool.definition.name, proxyTool);
        
        if (this.toolsetConfig.mode === "readWrite" || 
            (proxyTool.definition.annotations?.readOnlyHint !== false)) {
          this.enabledTools.add(proxyTool.definition.name);
        }
      }
    }

    this.notifyEnabledToolsChanged();
  }

  protected async notifyEnabledToolsChanged() {
    // Trigger the enabled tools changed callback
    this.enabledToolSubscriptions.forEach(callback => {
      callback({
        tools: Array.from(this.enabledTools)
          .map(toolName => this.tools.get(toolName)!)
          .filter(tool => tool)
          .map(tool => ({
            ...tool.definition,
            inputSchema: tool.definition.inputSchema as any,
          })),
      });
    });
  }

  getAllTools(): ToolCapability[] {
    return Array.from(this.tools.values());
  }

  getEnabledTools(): Set<string> {
    return this.enabledTools;
  }
}
