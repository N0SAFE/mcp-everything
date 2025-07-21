// Main MCP Proxy Server class
import { McpServer } from "../mcp-server.js";
import { BackendServerManager } from "./backend-server-manager.js";
import { ProxyToolManager } from "./proxy-tool-manager.js";
import { ProxyResourceManager } from "./proxy-resource-manager.js";
import { ProxyPromptManager } from "./proxy-prompt-manager.js";
import { ConfigurationManager } from "./configuration-manager.js";
import { DynamicServerCreator } from "./dynamic-server-creator.js";
import { OAuthConsolidationManager } from "./oauth-consolidation-manager.js";
import { ToolsetConfig, DynamicToolDiscoveryOptions } from "../types.js";
import { createTool, createToolDefinition } from "../utils/tools.js";
import { z } from "zod";
import { ToolCapability } from "../types";
import { DevToolManager } from "./dev-tool-manager.js";
import { Logger } from "../utils/logging.js";

export class ProxyMcpServer extends McpServer {
    private backendServerManager: BackendServerManager;
    private configurationManager: ConfigurationManager;
    private proxyToolManager: ProxyToolManager;
    private proxyResourceManager: ProxyResourceManager;
    private proxyPromptManager: ProxyPromptManager;
    private dynamicServerCreator: DynamicServerCreator;
    private devToolManager?: DevToolManager;
    private oauthConsolidationManager: OAuthConsolidationManager;

    // Static factory method for async initialization
    static async create({
        name,
        version,
        toolsetConfig,
        dynamicToolDiscovery,
        instructions,
        configurationManager
    }: {
        name: string;
        version: string;
        toolsetConfig: ToolsetConfig;
        dynamicToolDiscovery?: DynamicToolDiscoveryOptions;
        instructions?: string;
        configurationManager?: ConfigurationManager;
    }): Promise<ProxyMcpServer> {
        // Initialize configuration manager
        const configMgr = configurationManager || new ConfigurationManager();
        const proxyConfig = configMgr.getConfiguration();

        Logger.info("🚀 Starting MCP Proxy Server initialization...", { component: "proxy-mcp-server" });

        // Initialize OAuth consolidation manager first
        const oauthConsolidationManager = new OAuthConsolidationManager();

        // Force OAuth detection for known OAuth-enabled servers
        await oauthConsolidationManager.forceOAuthDetection(proxyConfig.servers);

        // Initialize backend server manager with OAuth support
        const backendServerManager = new BackendServerManager(proxyConfig.servers, oauthConsolidationManager);
        Logger.info("⏳ Waiting for all backend servers to connect...", { component: "proxy-mcp-server" });
        await backendServerManager.waitForInitialization();
        Logger.info("✅ All backend servers initialized", { 
            component: "proxy-mcp-server",
            connectedServers: backendServerManager.getConnectedServers().length
        });

        // Initialize dynamic server creator
        const dynamicServerCreator = new DynamicServerCreator();

        // Initialize proxy tool manager (this will now have access to all connected servers)
        Logger.info("⏳ Loading tools from backend servers...", { component: "proxy-mcp-server" });
        const proxyToolManager = new ProxyToolManager(name, backendServerManager, toolsetConfig, dynamicToolDiscovery);

        // Initialize proxy resource and prompt managers
        const proxyResourceManager = new ProxyResourceManager(backendServerManager);
        const proxyPromptManager = new ProxyPromptManager(backendServerManager);

        // Wait for proxy tools to be loaded
        await proxyToolManager.waitForInitialization();
        await proxyResourceManager.waitForInitialization();
        await proxyPromptManager.waitForInitialization();
        Logger.info("✅ All tools, resources, and prompts loaded from backend servers", { 
            component: "proxy-mcp-server",
            totalTools: proxyToolManager.getAllTools().length,
            enabledTools: proxyToolManager.getEnabledTools().size
        });

        // Create the proxy server instance
        const instance = new ProxyMcpServer(
            {
                name,
                version,
                toolsetConfig,
                dynamicToolDiscovery,
                instructions,
                oauthProvider: oauthConsolidationManager
            },
            { configurationManager: configMgr, backendServerManager, proxyToolManager, proxyResourceManager, proxyPromptManager, oauthConsolidationManager },
            dynamicServerCreator
        );

        Logger.info("🎯 MCP Proxy Server ready to accept requests!", { component: "proxy-mcp-server" });
        return instance;
    }

    private constructor(
        {
            name,
            version,
            toolsetConfig,
            dynamicToolDiscovery,
            instructions,
            oauthProvider
        }: {
            name: string;
            version: string;
            toolsetConfig: ToolsetConfig;
            dynamicToolDiscovery?: DynamicToolDiscoveryOptions;
            instructions?: string;
            oauthProvider?: any;
        },
        managers: {
            configurationManager: ConfigurationManager;
            backendServerManager: BackendServerManager;
            proxyToolManager: ProxyToolManager;
            proxyResourceManager: ProxyResourceManager;
            proxyPromptManager: ProxyPromptManager;
            oauthConsolidationManager: OAuthConsolidationManager;
        },
        dynamicServerCreator: DynamicServerCreator
    ) {
        // Create server management tools
        const serverManagementTools = ProxyMcpServer.createServerManagementTools(managers.configurationManager, managers.backendServerManager, managers.proxyToolManager);

        // Create dynamic server creation tools
        const dynamicServerTools = ProxyMcpServer.createDynamicServerTools(dynamicServerCreator, managers.configurationManager, managers.backendServerManager, managers.proxyToolManager);

        // Add server management and dynamic server tools to the proxy tool manager BEFORE getting all tools
        for (const tool of [...serverManagementTools, ...dynamicServerTools]) {
            managers.proxyToolManager.addTool(tool);
        }

        // Initialize and add development tools if in dev mode
        let devToolManager: DevToolManager | undefined;
        if (DevToolManager.isDevModeEnabled()) {
            Logger.info("🔧 Development mode enabled - initializing dev tools...", { component: "proxy-mcp-server" });
            devToolManager = new DevToolManager(managers.backendServerManager, managers.proxyToolManager, managers.configurationManager);

            const devTools = devToolManager.getDevTools();
            for (const tool of devTools) {
                managers.proxyToolManager.addTool(tool);
            }

            Logger.info(`🛠️ Added ${devTools.length} development tools`, { 
                component: "proxy-mcp-server",
                devToolsCount: devTools.length
            });
        }

        // Get all tools from the proxy tool manager (includes discovery tools + backend server tools + management tools)
        const allTools: ToolCapability[] = managers.proxyToolManager.getAllTools();

        Logger.info(`📊 Total tools available: ${allTools.length}`, { 
            component: "proxy-mcp-server",
            totalTools: allTools.length,
            enabledTools: managers.proxyToolManager.getEnabledTools().size
        });

        // Enhanced instructions for proxy server
        const devToolsInstructions = DevToolManager.isDevModeEnabled()
            ? `

### Development Tools (Dev Mode Only):
- \`dev_server_status\`: Get comprehensive server status and health information
- \`dev_error_logs\`: Retrieve recent error logs, warnings, and diagnostic information
- \`dev_tool_diagnostics\`: Analyze tool loading, execution issues, and availability
- \`dev_resource_diagnostics\`: Check resource loading issues and availability
- \`dev_backend_server_status\`: Get detailed status of all backend MCP servers
- \`dev_connection_diagnostics\`: Diagnose connection issues with backend servers
- \`dev_configuration_diagnostics\`: Validate server configuration and check for issues
- \`dev_memory_diagnostics\`: Monitor memory usage and performance metrics

These development tools provide detailed diagnostic information to help identify and resolve issues automatically.`
            : "";

        const proxyInstructions = `
# MCP Proxy Server

This is an MCP proxy server that provides access to multiple backend MCP servers through a unified interface.

## Available Capabilities:

### Dynamic Server Creation:
- \`proxy_create_custom_server\`: Create new MCP servers from natural language instructions
- \`proxy_list_generated_servers\`: List all dynamically created servers
- \`proxy_remove_generated_server\`: Remove a dynamically created server

### Server Management:
- \`proxy_server_list\`: List all configured backend servers and their status
- \`proxy_server_tools\`: List tools available from a specific backend server
- \`proxy_server_status\`: Get detailed status information for backend servers
- \`proxy_server_refresh\`: Refresh capabilities for a specific backend server
- \`proxy_config_add_server\`: Add a new backend server to the configuration
- \`proxy_config_remove_server\`: Remove a backend server from the configuration
- \`proxy_config_enable_server\`: Enable a backend server
- \`proxy_config_disable_server\`: Disable a backend server
${devToolsInstructions}

### Backend Server Tools:
All tools from connected backend servers are exposed with the format: \`{serverId}__{toolName}\`

For example, if a server with ID "weather" has a tool called "get_forecast", it will be available as "weather__get_forecast".

### Security:
- Each backend server can have its own security configuration
- Tools can be allowed/blocked per server
- Authentication requirements can be configured per server
- Global security policies can be applied

Use the server management tools to discover available backend servers and their capabilities.

${instructions || ""}`;

        // Aggregate resources and prompts from all backend servers for capabilities
        const aggregatedResources: any = {};
        const aggregatedPrompts: any = {};

        // Add placeholder entries to ensure capabilities are enabled
        // Real resources and prompts will be populated from backend servers
        aggregatedResources.definitions = {};
        aggregatedResources.handlers = {};
        aggregatedPrompts.definitions = {};
        aggregatedPrompts.handlers = {};

        super({
            name,
            version,
            capabilities: {
                tools: allTools,
                resources: aggregatedResources,
                prompts: aggregatedPrompts
            },
            toolsetConfig,
            dynamicToolDiscovery,
            instructions: proxyInstructions,
            oauthProvider: managers.oauthConsolidationManager,
            managers: {
                toolManager: managers.proxyToolManager,
                resourceManager: managers.proxyResourceManager,
                promptManager: managers.proxyPromptManager
            }
        });

        this.configurationManager = managers.configurationManager;
        this.backendServerManager = managers.backendServerManager;
        this.proxyToolManager = managers.proxyToolManager;
        this.proxyResourceManager = managers.proxyResourceManager;
        this.proxyPromptManager = managers.proxyPromptManager;
        this.dynamicServerCreator = dynamicServerCreator;
        this.devToolManager = devToolManager;
        this.oauthConsolidationManager = managers.oauthConsolidationManager;

        // Log all enabled tools on startup
        this.logEnabledToolsOnStartup();

        // Set up cleanup on shutdown
        process.on("SIGTERM", () => this.shutdownProxy());
        process.on("SIGINT", () => this.shutdownProxy());
    }

    private static createServerManagementTools(configManager: ConfigurationManager, backendServerManager: BackendServerManager, proxyToolManager: ProxyToolManager) {
        const addServerTool = createToolDefinition({
            name: "proxy_config_add_server",
            description: "Add a new backend MCP server to the configuration",
            inputSchema: z.object({
                id: z.string().describe("Unique identifier for the server"),
                name: z.string().describe("Human-readable name for the server"),
                description: z.string().optional().describe("Description of the server"),
                transportType: z.enum(["stdio", "http", "sse"]).describe("Transport type to use"),
                enabled: z.boolean().optional().default(true).describe("Whether to enable the server immediately"),
                stdio: z
                    .object({
                        command: z.string().describe("Command to execute"),
                        args: z.array(z.string()).optional().describe("Command arguments"),
                        env: z.record(z.string(), z.string()).optional().describe("Environment variables")
                    })
                    .optional(),
                http: z
                    .object({
                        url: z.string().describe("HTTP endpoint URL"),
                        headers: z.record(z.string(), z.string()).optional().describe("HTTP headers"),
                        timeout: z.number().optional().describe("Request timeout in milliseconds")
                    })
                    .optional(),
                sse: z
                    .object({
                        url: z.string().describe("SSE endpoint URL"),
                        headers: z.record(z.string(), z.string()).optional().describe("HTTP headers"),
                        timeout: z.number().optional().describe("Connection timeout in milliseconds")
                    })
                    .optional(),
                security: z
                    .object({
                        allowedTools: z.array(z.string()).optional().describe("List of allowed tool names"),
                        blockedTools: z.array(z.string()).optional().describe("List of blocked tool names"),
                        requireAuth: z.boolean().optional().describe("Whether authentication is required"),
                        allowedScopes: z.array(z.string()).optional().describe("Required authentication scopes")
                    })
                    .optional()
            }),
            annotations: {
                title: "Add Backend Server",
                readOnlyHint: false,
                destructiveHint: false,
                idempotentHint: false,
                openWorldHint: true
            }
        });

        const removeServerTool = createToolDefinition({
            name: "proxy_config_remove_server",
            description: "Remove a backend MCP server from the configuration",
            inputSchema: z.object({
                serverId: z.string().describe("ID of the server to remove")
            }),
            annotations: {
                title: "Remove Backend Server",
                readOnlyHint: false,
                destructiveHint: true,
                idempotentHint: true,
                openWorldHint: false
            }
        });

        const enableServerTool = createToolDefinition({
            name: "proxy_config_enable_server",
            description: "Enable a backend MCP server",
            inputSchema: z.object({
                serverId: z.string().describe("ID of the server to enable")
            }),
            annotations: {
                title: "Enable Backend Server",
                readOnlyHint: false,
                destructiveHint: false,
                idempotentHint: true,
                openWorldHint: false
            }
        });

        const disableServerTool = createToolDefinition({
            name: "proxy_config_disable_server",
            description: "Disable a backend MCP server",
            inputSchema: z.object({
                serverId: z.string().describe("ID of the server to disable")
            }),
            annotations: {
                title: "Disable Backend Server",
                readOnlyHint: false,
                destructiveHint: false,
                idempotentHint: true,
                openWorldHint: false
            }
        });

        return [
            createTool(addServerTool, async (params) => {
                try {
                    const serverConfig = {
                        id: params.id,
                        name: params.name,
                        description: params.description,
                        transportType: params.transportType,
                        enabled: params.enabled,
                        stdio: params.stdio,
                        http: params.http,
                        sse: params.sse,
                        security: params.security
                    };

                    configManager.addServer(serverConfig as any);

                    if (params.enabled) {
                        await backendServerManager.addServer(serverConfig as any);
                        await proxyToolManager.refreshServerTools(params.id);
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Server ${params.id} added successfully`
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error adding server: ${error instanceof Error ? error.message : String(error)}`
                            }
                        ]
                    };
                }
            }),

            createTool(removeServerTool, async (params) => {
                try {
                    await backendServerManager.removeServer(params.serverId);
                    configManager.removeServer(params.serverId);
                    await proxyToolManager.refreshServerTools(params.serverId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Server ${params.serverId} removed successfully`
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error removing server: ${error instanceof Error ? error.message : String(error)}`
                            }
                        ]
                    };
                }
            }),

            createTool(enableServerTool, async (params) => {
                try {
                    configManager.enableServer(params.serverId);
                    await backendServerManager.enableServer(params.serverId);
                    await proxyToolManager.refreshServerTools(params.serverId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Server ${params.serverId} enabled successfully`
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error enabling server: ${error instanceof Error ? error.message : String(error)}`
                            }
                        ]
                    };
                }
            }),

            createTool(disableServerTool, async (params) => {
                try {
                    configManager.disableServer(params.serverId);
                    await backendServerManager.disableServer(params.serverId);
                    await proxyToolManager.refreshServerTools(params.serverId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Server ${params.serverId} disabled successfully`
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error disabling server: ${error instanceof Error ? error.message : String(error)}`
                            }
                        ]
                    };
                }
            })
        ];
    }

    private static createDynamicServerTools(
        dynamicServerCreator: DynamicServerCreator,
        configManager: ConfigurationManager,
        backendServerManager: BackendServerManager,
        proxyToolManager: ProxyToolManager
    ) {
        const createCustomServerTool = createToolDefinition({
            name: "proxy_create_custom_server",
            description: "Create a new MCP server from natural language instructions. Supports OpenAPI/REST APIs, webhooks, databases, and custom servers.",
            inputSchema: z.object({
                instructions: z.string().describe("Natural language instructions describing what kind of MCP server to create and what it should do"),
                serverId: z.string().optional().describe("Optional custom server ID (if not provided, one will be generated)"),
                serverType: z.enum(["openapi", "webhook", "database", "custom"]).optional().describe("Specific server type to create (auto-detected if not provided)"),
                configuration: z
                    .object({
                        openApiUrl: z.string().optional().describe("URL to OpenAPI/Swagger specification"),
                        openApiSpec: z.any().optional().describe("OpenAPI specification as JSON object"),
                        baseUrl: z.string().optional().describe("Base URL for API calls"),
                        apiKey: z.string().optional().describe("API key for authentication"),
                        webhookUrl: z.string().optional().describe("Webhook endpoint URL"),
                        webhookSecret: z.string().optional().describe("Webhook secret for authentication"),
                        connectionString: z.string().optional().describe("Database connection string"),
                        databaseType: z.string().optional().describe("Database type (postgresql, mysql, sqlite, etc.)"),
                        schema: z.string().optional().describe("Database schema name"),
                        command: z.string().optional().describe("Command to execute for custom servers"),
                        args: z.array(z.string()).optional().describe("Command arguments"),
                        serverCode: z.string().optional().describe("Custom server code (JavaScript/Node.js)"),
                        env: z.record(z.string(), z.string()).optional().describe("Environment variables"),
                        requireAuth: z.boolean().optional().describe("Whether the server requires authentication")
                    })
                    .optional()
                    .describe("Server-specific configuration options")
            }),
            annotations: {
                title: "Create Custom MCP Server",
                readOnlyHint: false,
                destructiveHint: false,
                idempotentHint: false,
                openWorldHint: true
            }
        });

        const listGeneratedServersTool = createToolDefinition({
            name: "proxy_list_generated_servers",
            description: "List all dynamically created MCP servers",
            inputSchema: z.object({
                includeInstructions: z.boolean().optional().describe("Include the original instructions used to create each server")
            }),
            annotations: {
                title: "List Generated Servers",
                readOnlyHint: true,
                destructiveHint: false,
                idempotentHint: true,
                openWorldHint: false
            }
        });

        const removeGeneratedServerTool = createToolDefinition({
            name: "proxy_remove_generated_server",
            description: "Remove a dynamically created MCP server",
            inputSchema: z.object({
                serverId: z.string().describe("ID of the generated server to remove")
            }),
            annotations: {
                title: "Remove Generated Server",
                readOnlyHint: false,
                destructiveHint: true,
                idempotentHint: true,
                openWorldHint: false
            }
        });

        return [
            createTool(createCustomServerTool, async (params) => {
                try {
                    // Parse instructions if configuration is not fully specified
                    let instructions;
                    if (params.configuration && Object.keys(params.configuration).length > 0) {
                        // Use provided configuration
                        instructions = {
                            serverType: params.serverType || "custom",
                            description: params.instructions,
                            capabilities: [], // Will be inferred from serverType
                            configuration: params.configuration
                        };
                    } else {
                        // Parse from natural language instructions
                        instructions = dynamicServerCreator.parseInstructions(params.instructions);
                    }

                    // Override serverType if explicitly provided
                    if (params.serverType) {
                        instructions.serverType = params.serverType;
                    }

                    // Create the server
                    const serverConfig = await dynamicServerCreator.createServerFromInstructions(instructions, params.serverId);

                    // Add to configuration and backend manager
                    configManager.addServer(serverConfig);
                    await backendServerManager.addServer(serverConfig);

                    // Refresh proxy tools to include tools from the new server
                    setTimeout(async () => {
                        await proxyToolManager.refreshServerTools(serverConfig.id);
                    }, 2000); // Give the server time to start

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify(
                                    {
                                        success: true,
                                        serverId: serverConfig.id,
                                        serverName: serverConfig.name,
                                        description: serverConfig.description,
                                        serverType: instructions.serverType,
                                        capabilities: instructions.capabilities,
                                        message: `Successfully created ${instructions.serverType} MCP server '${serverConfig.name}' with ID '${serverConfig.id}'. The server will be available for use once it finishes initializing.`
                                    },
                                    null,
                                    2
                                )
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify(
                                    {
                                        success: false,
                                        error: error instanceof Error ? error.message : String(error),
                                        message: "Failed to create custom MCP server. Please check your instructions and configuration."
                                    },
                                    null,
                                    2
                                )
                            }
                        ]
                    };
                }
            }),

            createTool(listGeneratedServersTool, async (params) => {
                try {
                    const generatedServers = dynamicServerCreator.listGeneratedServers();

                    const serverList = generatedServers.map((server) => {
                        const basic = {
                            id: server.id,
                            name: server.name,
                            description: server.description,
                            serverType: server.instructions.serverType,
                            enabled: server.enabled,
                            generatedAt: server.generatedAt,
                            capabilities: server.instructions.capabilities
                        };

                        if (params.includeInstructions) {
                            return {
                                ...basic,
                                originalInstructions: server.instructions.description,
                                configuration: server.instructions.configuration
                            };
                        }

                        return basic;
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify(
                                    {
                                        generatedServers: serverList,
                                        totalGenerated: serverList.length,
                                        summary: {
                                            byType: serverList.reduce(
                                                (acc, server) => {
                                                    acc[server.serverType] = (acc[server.serverType] || 0) + 1;
                                                    return acc;
                                                },
                                                {} as Record<string, number>
                                            )
                                        }
                                    },
                                    null,
                                    2
                                )
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error listing generated servers: ${error instanceof Error ? error.message : String(error)}`
                            }
                        ]
                    };
                }
            }),

            createTool(removeGeneratedServerTool, async (params) => {
                try {
                    const server = dynamicServerCreator.getGeneratedServer(params.serverId);
                    if (!server) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Generated server ${params.serverId} not found`
                                }
                            ]
                        };
                    }

                    // Remove from backend manager and configuration
                    await backendServerManager.removeServer(params.serverId);
                    configManager.removeServer(params.serverId);

                    // Remove from dynamic server creator
                    dynamicServerCreator.removeGeneratedServer(params.serverId);

                    // Refresh proxy tools
                    await proxyToolManager.refreshServerTools(params.serverId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Generated server ${params.serverId} removed successfully`
                            }
                        ]
                    };
                } catch (error) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error removing generated server: ${error instanceof Error ? error.message : String(error)}`
                            }
                        ]
                    };
                }
            })
        ];
    }

    private async shutdownProxy() {
        Logger.info("Shutting down MCP Proxy Server...", { component: "proxy-mcp-server" });
        try {
            await this.backendServerManager.shutdown();
            await this.server.close();
            Logger.info("MCP Proxy Server shut down successfully", { component: "proxy-mcp-server" });
        } catch (error) {
            Logger.logError(error instanceof Error ? error : String(error), "Error during shutdown", { component: "proxy-mcp-server" });
        }
        process.exit(0);
    }

    // Getters for access to managers
    get backend() {
        return this.backendServerManager;
    }

    get config() {
        return this.configurationManager;
    }

    get tools() {
        return this.proxyToolManager;
    }

    private async logEnabledToolsOnStartup() {
        // Wait a moment for all servers to initialize
        setTimeout(async () => {
            try {
                const separator = "=".repeat(80);
                Logger.debug("🚀 MCP PROXY SERVER - ENABLED TOOLS SUMMARY", { component: "proxy-mcp-server" });

                // Get all enabled tools
                const allTools = this.proxyToolManager.getAllTools();
                const enabledTools = allTools.filter((tool) => this.proxyToolManager.getEnabledTools().has(tool.definition.name));

                Logger.debug("📊 SUMMARY", { 
                    component: "proxy-mcp-server",
                    totalTools: allTools.length,
                    enabledTools: enabledTools.length,
                    backendServers: this.backendServerManager.getConnectedServers().length
                });

                // Group tools by category
                const proxyManagementTools = enabledTools.filter((tool) => tool.definition.name.startsWith("proxy_"));
                const backendTools = enabledTools.filter((tool) => !tool.definition.name.startsWith("proxy_"));

                // Log proxy management tools
                if (proxyManagementTools.length > 0) {
                    Logger.debug(`🛠️  PROXY MANAGEMENT TOOLS (${proxyManagementTools.length})`, { 
                        component: "proxy-mcp-server",
                        toolCount: proxyManagementTools.length,
                        tools: proxyManagementTools.map(tool => ({
                            name: tool.definition.name,
                            description: tool.definition.description
                        }))
                    });
                }

                // Group backend tools by server
                if (backendTools.length > 0) {
                    Logger.debug(`🔧 BACKEND SERVER TOOLS (${backendTools.length})`, { 
                        component: "proxy-mcp-server",
                        toolCount: backendTools.length
                    });

                    const toolsByServer: { [serverId: string]: any[] } = {};
                    backendTools.forEach((tool) => {
                        if ("serverId" in tool.definition) {
                            const { serverId } = tool.definition as any;
                            if (!toolsByServer[serverId]) {
                                toolsByServer[serverId] = [];
                            }
                            toolsByServer[serverId].push(tool);
                        } else {
                            // Handle tools without serverId (like discovery tools)
                            if (!toolsByServer["core"]) {
                                toolsByServer["core"] = [];
                            }
                            toolsByServer["core"].push(tool);
                        }
                    });

                    Object.entries(toolsByServer).forEach(([serverId, tools]) => {
                        const serverConnection = this.backendServerManager.getServerConnection(serverId);
                        const serverName = serverConnection?.config.name || serverId;
                        const isConnected = serverConnection?.status.connected || false;
                        const connectionStatus = isConnected ? "🟢 CONNECTED" : "🔴 DISCONNECTED";

                        Logger.debug(`📡 ${serverName} (${serverId}) - ${connectionStatus}`, {
                            component: "proxy-mcp-server",
                            serverId,
                            serverName,
                            connected: isConnected,
                            toolCount: tools.length,
                            tools: tools.map(tool => {
                                const originalName = "originalName" in tool.definition ? (tool.definition as any).originalName : tool.definition.name;
                                return {
                                    originalName,
                                    proxyName: tool.definition.name
                                };
                            })
                        });
                    });
                }

                // Log server statuses
                const serverStatuses = this.backendServerManager.getServerStatuses();
                if (serverStatuses.length > 0) {
                    Logger.debug("🌐 SERVER STATUS DETAILS", {
                        component: "proxy-mcp-server",
                        servers: serverStatuses.map(status => ({
                            id: status.id,
                            connected: status.connected,
                            toolsCount: status.toolsCount || 0,
                            lastError: status.lastError
                        }))
                    });
                }

                // Log security information
                const config = this.configurationManager.getConfiguration();
                if (config.security?.globalBlockedTools?.length) {
                    Logger.debug("🔒 SECURITY", {
                        component: "proxy-mcp-server",
                        globallyBlockedTools: config.security.globalBlockedTools
                    });
                }

                Logger.info("🎯 Ready to receive tool calls!", { component: "proxy-mcp-server" });
            } catch (error) {
                Logger.logError(error instanceof Error ? error : String(error), "Error logging enabled tools", { component: "proxy-mcp-server" });
            }
        }, 2000); // Wait 2 seconds for servers to connect
    }

    get serverCreator() {
        return this.dynamicServerCreator;
    }
}
