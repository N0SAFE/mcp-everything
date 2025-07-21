#!/usr/bin/env node

import { ProxyMcpServer } from "../manager/proxy-mcp-server.js";
import { ConfigurationManager } from "../manager/configuration-manager.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfigFromCommanderAndEnv } from "./config.js";

// Check if debug logging is enabled
const DEBUG_ENABLED = process.env.MCP_DEBUG === "true" || process.env.NODE_ENV === "development";

// Debug logging function that only outputs when debug is enabled
function debugLog(...args: any[]) {
  if (DEBUG_ENABLED) {
    console.error(...args);
  }
}

async function main() {
  try {
    // Load configuration
    let configManager: ConfigurationManager;
    
    if (process.env.MCP_PROXY_USE_ENV === "true") {
      configManager = ConfigurationManager.createFromEnvironment();
      debugLog("Using configuration from environment variables");
    } else {
      configManager = new ConfigurationManager(process.env.MCP_PROXY_CONFIG_PATH);
      debugLog(`Using configuration from file: ${process.env.MCP_PROXY_CONFIG_PATH || "./mcp-proxy-config.json"}`);
    }

    // Get toolset configuration from command line/environment
    const toolsetConfig = getConfigFromCommanderAndEnv();

    // Create proxy server with async initialization
    debugLog("🚀 Initializing MCP Proxy Server...");
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
    
    // Notify the client that tools, resources, and prompts are available after initialization
    server.server.sendToolListChanged();
    server.server.sendResourceListChanged();
    server.server.sendPromptListChanged();
    
    server.server.sendLoggingMessage({
      level: "info",
      data: "MCP Proxy Server started successfully",
    });

    debugLog("MCP Proxy Server running on stdio");
    debugLog(`Configured servers: ${configManager.getServers().length}`);
    debugLog(`Active servers: ${server.backend.getConnectedServers().length}`);

  } catch (error) {
    console.error("Failed to start MCP Proxy Server:", error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on("SIGINT", () => {
  debugLog("Received SIGINT, shutting down gracefully...");
  process.exit(0);
});

process.on("SIGTERM", () => {
  debugLog("Received SIGTERM, shutting down gracefully...");
  process.exit(0);
});

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
