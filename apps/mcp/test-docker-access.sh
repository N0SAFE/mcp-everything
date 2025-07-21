#!/bin/bash

# Docker Test Script for MCP Container
# This script tests Docker functionality from within the MCP container

echo "🐳 Docker Access Test for MCP Container"
echo "========================================"

# Test 1: Check if Docker CLI is available
echo "1. Testing Docker CLI availability..."
if command -v docker >/dev/null 2>&1; then
    echo "   ✅ Docker CLI is installed"
    docker --version
else
    echo "   ❌ Docker CLI not found"
    exit 1
fi

# Test 2: Check Docker socket access
echo ""
echo "2. Testing Docker socket access..."
if [ -S /var/run/docker.sock ]; then
    echo "   ✅ Docker socket exists"
    ls -la /var/run/docker.sock
else
    echo "   ❌ Docker socket not found"
    exit 1
fi

# Test 3: Test Docker daemon communication
echo ""
echo "3. Testing Docker daemon communication..."
if docker info >/dev/null 2>&1; then
    echo "   ✅ Can communicate with Docker daemon"
    echo "   Docker info:"
    docker info | grep -E "(Server Version|Operating System|Architecture)" | sed 's/^/   /'
else
    echo "   ❌ Cannot communicate with Docker daemon"
    echo "   Error details:"
    docker info 2>&1 | sed 's/^/   /'
    exit 1
fi

# Test 4: List containers
echo ""
echo "4. Testing container listing..."
echo "   Current containers:"
if docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | head -5; then
    echo "   ✅ Container listing successful"
else
    echo "   ❌ Container listing failed"
fi

# Test 5: Test container creation (dry run)
echo ""
echo "5. Testing container creation capability..."
if docker run --rm --name mcp-test-container alpine:latest echo "Hello from test container" >/dev/null 2>&1; then
    echo "   ✅ Can create and run containers"
else
    echo "   ❌ Cannot create containers"
    echo "   This might be due to permission issues"
fi

# Test 6: Check npm and npx
echo ""
echo "6. Testing npm/npx availability..."
if command -v npm >/dev/null 2>&1; then
    echo "   ✅ npm is available: $(npm --version)"
else
    echo "   ❌ npm not found"
fi

if command -v npx >/dev/null 2>&1; then
    echo "   ✅ npx is available: $(npx --version)"
else
    echo "   ❌ npx not found"
fi

# Test 7: Test npx with a simple package
echo ""
echo "7. Testing npx functionality..."
if timeout 10 npx --version >/dev/null 2>&1; then
    echo "   ✅ npx is working"
    echo "   Testing npx with a package..."
    if timeout 30 npx --yes cowsay "MCP Container Ready!" 2>/dev/null; then
        echo "   ✅ npx can install and run packages"
    else
        echo "   ⚠️  npx working but package installation might be slow"
    fi
else
    echo "   ❌ npx not working properly"
fi

echo ""
echo "🎉 Docker and NPX access test completed!"
echo ""
echo "📋 Summary:"
if docker info >/dev/null 2>&1; then
    echo "  ✅ Docker: Fully functional"
else
    echo "  ⚠️  Docker: Socket permissions issue (common on Windows/WSL2)"
    echo "     Solutions:"
    echo "     - Run 'sudo chmod 666 /var/run/docker.sock' on host"
    echo "     - Enable Docker Desktop TCP API (port 2375)"
    echo "     - Use 'docker run --privileged' for testing"
fi

if command -v npx >/dev/null 2>&1; then
    echo "  ✅ NPX: Ready for MCP server installation"
else
    echo "  ❌ NPX: Not available"
fi

echo ""
echo "🚀 Usage examples:"
echo "  # List all containers (if Docker working):"
echo "  docker ps -a"
echo ""
echo "  # Install and run MCP servers with NPX:"
echo "  npx -y @modelcontextprotocol/server-filesystem ."
echo "  npx -y @modelcontextprotocol/server-git ."
echo "  npx -y @modelcontextprotocol/server-postgres"
echo ""
echo "  # Use docker-compose from host project:"
echo "  docker-compose -f /path/to/docker-compose.yml up"
echo ""
echo "📖 See documentation: /app/docs/DOCKER-IN-DOCKER-MCP.md"
