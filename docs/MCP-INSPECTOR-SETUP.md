# MCP Inspector Setup

## Overview

The MCP Inspector is a web-based debugging tool for Model Context Protocol (MCP) servers. It provides a user-friendly interface to test server connections, explore available tools, and debug MCP interactions.

## Port Configuration

The MCP Inspector uses two separate ports for different purposes:

### Port 3001 - Web UI (CLIENT_PORT)
- **Purpose**: Web interface for the MCP Inspector
- **Access**: http://localhost:3001
- **Description**: This is where you open your browser to interact with the inspector interface
- **Environment Variable**: `CLIENT_PORT=3001`

### Port 3002 - MCP Server Endpoint (SERVER_PORT)  
- **Purpose**: MCP protocol endpoint for server communication
- **Access**: Used internally by the inspector to connect to MCP servers
- **Description**: The actual MCP server that hosts your proxy configuration
- **Environment Variable**: `SERVER_PORT=3002`

## Environment Variables

```bash
# MCP Inspector Configuration
CLIENT_PORT=3001                    # Web UI port
SERVER_PORT=3002                   # MCP server port
MCP_INSPECTOR_HOST=0.0.0.0         # Allow external connections
MCP_INSPECTOR_CLIENT_PORT=3001     # Docker port mapping for UI
MCP_INSPECTOR_SERVER_PORT=3002     # Docker port mapping for server
```

## Docker Setup

### Starting the MCP Inspector

```bash
# Start MCP Inspector service
docker-compose -f docker-compose.mcp.yml up

# Or with rebuild
docker-compose -f docker-compose.mcp.yml up --build
```

### Accessing the Inspector

1. **Open Web Interface**: Navigate to http://localhost:3001
2. **Configure Server Connection**: 
   - Server URL: `http://localhost:3002`
   - This connects the inspector UI to your MCP proxy server

## How It Works

```
Browser → Port 3001 (Web UI) → MCP Inspector Frontend
                              ↓
                              Port 3002 (MCP Server) → Proxy Server → Backend MCP Servers
```

1. **Web UI (Port 3001)**: You interact with the inspector interface in your browser
2. **MCP Server (Port 3002)**: The inspector connects to this endpoint to communicate with your MCP proxy server
3. **Proxy Server**: Routes requests to the appropriate backend MCP servers based on your configuration

## Configuration Files

- **MCP Config**: `apps/mcp/mcp-proxy-config.json` - Defines which MCP servers to proxy
- **Docker Config**: `docker-compose.mcp.yml` - Container setup and port mapping
- **Inspector Config**: Environment variables in the Docker service

## Troubleshooting

### Common Issues

1. **Port Already in Use**:
   ```bash
   # Check what's using the port
   netstat -ano | findstr :3001
   # Kill the process or change the port
   ```

2. **Cannot Connect to MCP Server**:
   - Verify port 3002 is accessible
   - Check MCP proxy server is running
   - Ensure firewall allows connections

3. **Web UI Not Loading**:
   - Verify port 3001 is exposed in Docker
   - Check container logs: `docker-compose -f docker-compose.mcp.yml logs`

### Logs

```bash
# View inspector logs
docker-compose -f docker-compose.mcp.yml logs -f mcp-inspector-dev

# View just startup logs
docker-compose -f docker-compose.mcp.yml logs mcp-inspector-dev | head -50
```

## Development Workflow

1. Start the inspector: `docker-compose -f docker-compose.mcp.yml up`
2. Open http://localhost:3001 in your browser
3. Configure connection to http://localhost:3002
4. Browse available tools and test connections
5. Make changes to MCP config and restart to see updates

## Tool Discovery

The inspector will automatically discover and display:
- All available MCP servers in your proxy configuration
- Tools provided by each server
- Server connection status
- Tool schemas and capabilities

This makes it easy to understand what's available in your MCP environment and test functionality before integrating it into your applications.
