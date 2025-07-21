#!/usr/bin/env node

import { ProxyMcpServer } from "../manager/proxy-mcp-server.js";
import { ConfigurationManager } from "../manager/configuration-manager.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfigFromCommanderAndEnv } from "./config.js";
import { Logger } from "../utils/logging.js";

async function main() {
  try {
    // Load configuration
    let configManager: ConfigurationManager;
    
    if (process.env.MCP_PROXY_USE_ENV === "true") {
      configManager = ConfigurationManager.createFromEnvironment();
      Logger.debug("Using configuration from environment variables", { component: "proxy-stdio" });
    } else {
      configManager = new ConfigurationManager(process.env.MCP_PROXY_CONFIG_PATH);
      Logger.debug(`Using configuration from file: ${process.env.MCP_PROXY_CONFIG_PATH || "./mcp-proxy-config.json"}`, { 
        component: "proxy-stdio",
        configPath: process.env.MCP_PROXY_CONFIG_PATH || "./mcp-proxy-config.json"
      });
    }

    // Get toolset configuration from command line/environment
    const toolsetConfig = getConfigFromCommanderAndEnv();

    // Create proxy server with async initialization
    Logger.info("🚀 Initializing MCP Proxy Server...", { component: "proxy-stdio" });
    const server = await ProxyMcpServer.create({
      name: "mcp-proxy-server",
      version: "1.0.0",
      toolsetConfig: toolsetConfig.toolsetConfig || { mode: "readWrite" },
      dynamicToolDiscovery: toolsetConfig.dynamicToolDiscovery || { enabled: true },
      configurationManager: configManager,
      instructions: `
## MCP Proxy Server

This server acts as a reverse proxy for multiple MCP servers, providing:
- Unified access to tools from multiple backend servers
- Dynamic server discovery and management
- Security and access control
- Server health monitoring and management
- Dynamic server creation from natural language instructions

### Quick Start:
1. Use \`proxy_server_list\` to see all configured backend servers
2. Use \`proxy_server_tools <serverId>\` to see tools from a specific server
3. Use tools from backend servers with the format: \`{serverId}__{toolName}\`
4. Create new servers dynamically with \`proxy_create_custom_server\`

### Dynamic Server Creation:
- Create OpenAPI/REST API servers from specifications
- Create webhook servers for HTTP POST operations  
- Create database servers for SQL operations
- Create custom servers from code or commands

### Server Management:
- Add new servers with \`proxy_config_add_server\`
- Enable/disable servers with \`proxy_config_enable_server\`/\`proxy_config_disable_server\`
- Remove servers with \`proxy_config_remove_server\`
- Check server status with \`proxy_server_status\`

### Example Configuration:
Create a config file with servers like:
\`\`\`json
{
  "servers": [
    {
      "id": "weather",
      "name": "Weather Server",
      "transportType": "stdio",
      "enabled": true,
      "stdio": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-weather"]
      }
    }
  ]
}
\`\`\`

### Example Dynamic Server Creation:
\`\`\`
proxy_create_custom_server({
  "instructions": "Create a server to connect to the GitHub API for repository management",
  "serverType": "openapi", 
  "configuration": {
    "openApiUrl": "https://api.github.com/openapi.yaml",
    "baseUrl": "https://api.github.com",
    "apiKey": "your-github-token"
  }
})
\`\`\`
`,
    });

    const transport = new StdioServerTransport();
    await server.server.connect(transport);
    
    // Set up the logger with the MCP server instance
    Logger.setMcpServer(server.server);
    
    // Notify the client that tools, resources, and prompts are available after initialization
    server.server.sendToolListChanged();
    server.server.sendResourceListChanged();
    server.server.sendPromptListChanged();
    
    server.server.sendLoggingMessage({
      level: "info",
      data: "MCP Proxy Server started successfully",
    });

    Logger.info("MCP Proxy Server running on stdio", { 
      component: "proxy-stdio",
      configuredServers: configManager.getServers().length,
      activeServers: server.backend.getConnectedServers().length
    });

  } catch (error) {
    Logger.critical("Failed to start MCP Proxy Server", { 
      component: "proxy-stdio", 
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    console.error("Failed to start MCP Proxy Server:", error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on("SIGINT", () => {
  Logger.info("Received SIGINT, shutting down gracefully...", { component: "proxy-stdio", signal: "SIGINT" });
  process.exit(0);
});

process.on("SIGTERM", () => {
  Logger.info("Received SIGTERM, shutting down gracefully...", { component: "proxy-stdio", signal: "SIGTERM" });
  process.exit(0);
});

main().catch((err) => {
  Logger.critical("Fatal error in main process", { 
    component: "proxy-stdio", 
    error: err instanceof Error ? err.message : String(err),
    stack: err instanceof Error ? err.stack : undefined
  });
  console.error("Fatal error:", err);
  process.exit(1);
});
