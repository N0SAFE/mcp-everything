# MCP (Model Context Protocol) Development Setup

This directory contains the MCP proxy server and development tools for the Model Context Protocol integration.

## 🚀 Quick Start

### Local Development
```bash
# Run MCP proxy server locally
bun mcp dev

# Run MCP inspector locally  
bun mcp inspect

# Run MCP proxy with inspector
bun mcp inspect:proxy
```

### Docker Development
```bash
# Start MCP inspector in Docker
bun run dev:mcp

# Build and start MCP inspector in Docker
bun run dev:mcp:build

# View MCP inspector logs
bun run dev:mcp:logs

# Stop MCP inspector
bun run dev:mcp:down

# Shell into MCP container
bun run dev:mcp:run
```

## 📖 Available Services

### MCP Proxy Server
- **Port:** Runs on stdio (no HTTP port)
- **Purpose:** Acts as a reverse proxy for multiple MCP servers
- **Config:** `mcp-proxy-config.json`

### MCP Inspector
- **Port:** 3001 (configurable via `MCP_INSPECTOR_PORT`)
- **Purpose:** Web UI for testing and debugging MCP servers
- **URL:** http://localhost:3001

## ⚙️ Configuration

### Environment Variables
```bash
# MCP Inspector port
MCP_INSPECTOR_PORT=3001

# MCP proxy configuration file path
MCP_PROXY_CONFIG_PATH=./mcp-proxy-config.json
```

### MCP Proxy Configuration
The proxy server is configured via `mcp-proxy-config.json` which includes:

- **Context7** - Documentation fetching
- **Maven Dependencies** - Maven package info  
- **MarkItDown** - File format conversion
- **DeepWiki** - GitHub repository documentation
- **Sequential Thinking** - Structured problem solving
- **Memory** - Knowledge graph storage
- **File System** - Secure file operations
- And more...

## 🛠️ Development Commands

```bash
# Build TypeScript
bun mcp build

# Run tests
bun mcp test

# Start proxy server
bun mcp proxy

# Start HTTP server
bun mcp http-server

# Enhanced proxy example
bun mcp enhanced-proxy
```

## 🔍 Available Tools

When the proxy server starts, it logs all enabled tools:

### Proxy Management Tools
- `proxy_server_list` - List all backend servers
- `proxy_server_tools` - List tools from specific servers  
- `proxy_server_status` - Get server status
- `proxy_config_add_server` - Add new servers dynamically
- `proxy_create_custom_server` - Create servers from natural language

### Backend Server Tools
Tools from connected servers are available with the format: `{serverId}__{toolName}`

Example: `context7__get-library-docs`, `memory__create_entities`

## 🐳 Docker Configuration

The MCP service is containerized with:

- **Base Image:** `oven/bun:latest`
- **Python Support:** For `uvx` and Python-based MCP servers
- **Volume Mounts:** Source code for hot reloading
- **Network:** Shared with other services via `app_network_dev`

## 📁 File Structure

```
apps/mcp/
├── src/
│   ├── bin/              # Executable scripts
│   ├── manager/          # Core management classes
│   ├── utils/            # Utility functions
│   └── types.ts          # TypeScript types
├── mcp-proxy-config.json # Main configuration
├── package.json          # Dependencies and scripts
└── README.md             # This file
```

## 🔧 Troubleshooting

### Common Issues

1. **Port conflicts**: Change `MCP_INSPECTOR_PORT` if 3001 is occupied
2. **Server connection failures**: Check that the MCP server packages exist and are properly installed
3. **Permission issues**: Ensure proper file permissions for volume mounts

### Debugging

1. **View logs**: `bun run dev:mcp:logs`
2. **Check server status**: Use `proxy_server_status` tool
3. **Refresh capabilities**: Use `proxy_server_refresh` tool
4. **Inspector UI**: Open http://localhost:3001 for visual debugging

## 🚀 Production Deployment

For production deployment, the MCP services can be configured to run as:
- Standalone Docker containers
- Kubernetes pods  
- Server processes with proper process management

Ensure proper security configurations and API key management for production use.
