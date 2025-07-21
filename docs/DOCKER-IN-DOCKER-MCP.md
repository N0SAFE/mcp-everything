# Docker-in-Docker Support for MCP Server

## Overview

The MCP server container now supports Docker access, allowing it to manage Docker containers on the host machine while running inside a container itself. This enables advanced MCP server capabilities like:

- Running containerized MCP servers dynamically
- Managing Docker-based services from MCP tools
- Using `npx` to install and run Node.js-based MCP servers

## Features Added

### 1. NPX Support
- Full Node.js installation with npm and npx
- Ability to install and run MCP servers via npx
- Example: `npx -y @modelcontextprotocol/server-filesystem .`

### 2. Docker CLI Access
- Docker CLI installed in container
- Docker socket mounted from host
- Docker Compose support
- Full container management capabilities

### 3. Security Configuration
- Non-root user with Docker group access
- Proper permissions for Docker socket
- Isolated user environment

## Configuration

### Docker Compose Setup

The MCP container is configured with:

```yaml
volumes:
  # Docker socket for host communication
  - /var/run/docker.sock:/var/run/docker.sock
  # Docker CLI binary (if needed)
  - /usr/bin/docker:/usr/bin/docker:ro

environment:
  # Docker configuration
  - DOCKER_HOST=unix:///var/run/docker.sock
  - COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-nextjs-directus}
```

### Dockerfile Features

```dockerfile
# Node.js with npm/npx
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs

# Docker CLI installation
RUN apt-get install -y docker-ce-cli

# Docker Compose installation
RUN curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
```

## Usage Examples

### 1. Testing Docker Access

Run the test script to verify Docker functionality:

```bash
# From within the container
./test-docker-access.sh
```

### 2. Using NPX for MCP Servers

```bash
# Install and run filesystem server
npx -y @modelcontextprotocol/server-filesystem /tmp

# Install and run git server
npx -y @modelcontextprotocol/server-git .

# Install and run postgres server
npx -y @modelcontextprotocol/server-postgres
```

### 3. Docker Container Management

```bash
# List containers on host
docker ps

# Start a new container
docker run --rm alpine:latest echo "Hello from MCP!"

# Use docker-compose
docker-compose -f ../docker-compose.yml ps

# Build and run custom containers
docker build -t my-mcp-server .
docker run --rm my-mcp-server
```

### 4. Dynamic MCP Server Creation

The container can now dynamically create and manage MCP servers:

```javascript
// Example: Create a containerized MCP server
const serverContainer = await docker.run({
  image: 'node:alpine',
  command: ['npx', '@modelcontextprotocol/server-filesystem', '/data'],
  volumes: ['/host/data:/data'],
  network: 'mcp-network'
});
```

## Security Considerations

### 1. Docker Socket Access
- The container has full Docker access (equivalent to root on host)
- Only use in trusted development environments
- Consider Docker-in-Docker for production

### 2. User Permissions
- Container runs as non-root user with Docker group access
- Files created maintain proper ownership
- Network isolation maintained

### 3. Production Deployment
For production, consider:
- Using Docker-in-Docker instead of socket mounting
- Implementing additional access controls
- Using specific Docker API permissions

## Troubleshooting

### Common Issues

1. **Docker Permission Denied**
   ```bash
   # On Windows/WSL2, you may need to fix Docker socket permissions:
   
   # Option 1: Run container with privileged mode (temporary fix)
   docker run --privileged ...
   
   # Option 2: Fix Docker socket permissions on host
   sudo chmod 666 /var/run/docker.sock
   
   # Option 3: Add your user to docker group on host
   sudo usermod -aG docker $USER
   # Then restart Docker Desktop or WSL2
   
   # Check Docker socket permissions
   ls -la /var/run/docker.sock
   
   # Verify user is in docker group
   groups
   ```

2. **Windows/WSL2 Specific Issues**
   ```bash
   # Ensure Docker Desktop is running
   # Enable "Expose daemon on tcp://localhost:2375 without TLS" in Docker Desktop settings
   
   # Or use TCP connection instead of socket
   export DOCKER_HOST=tcp://localhost:2375
   
   # Test Docker connection
   docker info
   ```

3. **NPX Installation Fails**
   ```bash
   # Check npm configuration
   npm config list
   
   # Clear npm cache
   npm cache clean --force
   
   # Update npm to latest
   npm install -g npm@latest
   ```

3. **Container Can't Access Host Docker**
   ```bash
   # Test Docker connectivity
   docker info
   
   # Check socket mounting
   ls -la /var/run/docker.sock
   ```

### Debug Commands

```bash
# Test Docker access
./test-docker-access.sh

# Check container environment
env | grep -i docker

# Verify installations
node --version
npm --version
docker --version
docker-compose --version

# Test npx functionality
npx --version
npx --yes cowsay "Testing npx"
```

### Logs and Monitoring

```bash
# View container startup logs
docker-compose -f docker-compose.mcp.yml logs mcp-inspector-dev

# Monitor Docker events from container
docker events

# Check container resource usage
docker stats
```

## Advanced Usage

### 1. Custom MCP Server Deployment

```bash
# Create a custom MCP server container
cat > Dockerfile.custom-mcp << EOF
FROM node:alpine
RUN npm install -g @modelcontextprotocol/server-filesystem
CMD ["npx", "@modelcontextprotocol/server-filesystem", "/data"]
EOF

# Build and run
docker build -f Dockerfile.custom-mcp -t custom-mcp .
docker run --rm -v /host/data:/data custom-mcp
```

### 2. Multi-Container MCP Setup

```yaml
# docker-compose.mcp-extended.yml
services:
  mcp-proxy:
    # Main MCP container with Docker access
    
  mcp-filesystem:
    image: node:alpine
    command: ["npx", "@modelcontextprotocol/server-filesystem", "/shared"]
    
  mcp-database:
    image: node:alpine
    command: ["npx", "@modelcontextprotocol/server-postgres"]
```

### 3. Hot-Reload MCP Development

```bash
# Watch for changes and restart MCP servers
nodemon --watch src --exec "npx @modelcontextprotocol/server-custom"

# Use Docker for isolated testing
docker run --rm -v $(pwd):/workspace node:alpine npx @modelcontextprotocol/server-test
```

## Related Documentation

- [MCP Inspector Setup](./MCP-INSPECTOR-SETUP.md)
- [GitHub MCP Setup](./GITHUB-MCP-SETUP.md)
- [Development Workflow](./DEVELOPMENT-WORKFLOW.md)
- [Docker Build Strategies](./DOCKER-BUILD-STRATEGIES.md)
