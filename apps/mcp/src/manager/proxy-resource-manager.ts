// Check if debug logging is enabled
const DEBUG_ENABLED = process.env.MCP_DEBUG === "true" || process.env.NODE_ENV === "development";

// Debug logging function that only outputs when debug is enabled
function debugLog(...args: any[]) {
  if (DEBUG_ENABLED) {
    console.error(...args);
  }
}

import { BackendServerManager } from './backend-server-manager.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";

export interface ProxyResourceDefinition {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export class ProxyResourceManager {
  private backendServerManager: BackendServerManager;

  constructor(backendServerManager: BackendServerManager) {
    this.backendServerManager = backendServerManager;
  }

  async waitForInitialization(): Promise<void> {
    await this.backendServerManager.waitForInitialization();
  }

  hasResources(): boolean {
    // Always return true to enable resource capabilities
    // We'll check at runtime if backend servers have resources
    return true;
  }

  async listResources(request?: { params?: { cursor?: string } }): Promise<any> {
    // Aggregate resources from all backend servers
    const allResources: ProxyResourceDefinition[] = [];
    
    const connections = this.backendServerManager.getAllConnections();
    
    for (const connection of connections) {
      try {
        if (connection.client && connection.resources.size > 0) {
          // Get resources from this backend server
          for (const [uri, resource] of connection.resources) {
            // Prefix the URI with server ID to avoid conflicts
            const prefixedResource = {
              ...resource,
              uri: `${connection.config.id}__${resource.uri}`,
              name: resource.name ? `[${connection.config.id}] ${resource.name}` : `[${connection.config.id}] ${resource.uri}`,
            };
            allResources.push(prefixedResource);
          }
        }
      } catch (error) {
        debugLog(`Error getting resources from server ${connection.config.id}:`, error);
      }
    }

    debugLog(`ProxyResourceManager: Found ${allResources.length} total resources`);

    return {
      resources: allResources,
    };
  }

  async readResource(request: { params: { uri: string } }): Promise<any> {
    const uri = request.params.uri;
    
    // Check if this is a prefixed URI from a backend server
    const match = uri.match(/^([^_]+)__(.+)$/);
    if (!match) {
      throw new McpError(ErrorCode.InvalidRequest, `Invalid resource URI format: ${uri}`);
    }

    const [, serverId, originalUri] = match;
    const connection = this.backendServerManager.getServerConnection(serverId);
    
    if (!connection || !connection.client) {
      throw new McpError(ErrorCode.InvalidRequest, `Backend server not found or not connected: ${serverId}`);
    }

    try {
      // Delegate to the backend server
      const result = await connection.client.readResource({ uri: originalUri });
      debugLog(`ProxyResourceManager: Read resource ${uri} from server ${serverId}`);
      return {
        contents: [
          {
            uri: uri, // Use the prefixed URI
            mimeType: result.contents?.[0]?.mimeType || "text/plain",
            text: result.contents?.[0]?.text,
            blob: result.contents?.[0]?.blob,
          }
        ]
      };
    } catch (error) {
      debugLog(`Error reading resource ${uri} from server ${serverId}:`, error);
      throw new McpError(ErrorCode.InternalError, `Failed to read resource from backend server: ${error}`);
    }
  }

  async subscribeToResource(request: { 
    params: { uri: string }; 
    meta?: { sessionId?: string } 
  }): Promise<{ success: boolean }> {
    const uri = request.params.uri;
    
    // Check if this is a prefixed URI from a backend server
    const match = uri.match(/^([^_]+)__(.+)$/);
    if (!match) {
      throw new McpError(ErrorCode.InvalidRequest, `Invalid resource URI format: ${uri}`);
    }

    const [, serverId, originalUri] = match;
    const connection = this.backendServerManager.getServerConnection(serverId);
    
    if (!connection || !connection.client) {
      throw new McpError(ErrorCode.InvalidRequest, `Backend server not found or not connected: ${serverId}`);
    }

    try {
      // For now, just return success since subscription support varies
      debugLog(`ProxyResourceManager: Subscribed to resource ${uri} from server ${serverId}`);
      return { success: true };
    } catch (error) {
      debugLog(`Error subscribing to resource ${uri} from server ${serverId}:`, error);
      throw new McpError(ErrorCode.InternalError, `Failed to subscribe to resource from backend server: ${error}`);
    }
  }

  async unsubscribeFromResource(request: { 
    params: { uri: string }; 
    meta?: { sessionId?: string } 
  }): Promise<{ success: boolean }> {
    const uri = request.params.uri;
    
    // Check if this is a prefixed URI from a backend server
    const match = uri.match(/^([^_]+)__(.+)$/);
    if (!match) {
      throw new McpError(ErrorCode.InvalidRequest, `Invalid resource URI format: ${uri}`);
    }

    const [, serverId, originalUri] = match;
    const connection = this.backendServerManager.getServerConnection(serverId);
    
    if (!connection || !connection.client) {
      throw new McpError(ErrorCode.InvalidRequest, `Backend server not found or not connected: ${serverId}`);
    }

    try {
      // For now, just return success since subscription support varies
      debugLog(`ProxyResourceManager: Unsubscribed from resource ${uri} from server ${serverId}`);
      return { success: true };
    } catch (error) {
      debugLog(`Error unsubscribing from resource ${uri} from server ${serverId}:`, error);
      throw new McpError(ErrorCode.InternalError, `Failed to unsubscribe from resource from backend server: ${error}`);
    }
  }
}
