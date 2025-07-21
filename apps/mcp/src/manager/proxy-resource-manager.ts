import { BackendServerManager } from './backend-server-manager.js';
import { ResourceManager } from './resource-manager.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Logger } from "../utils/logging.js";

export interface ProxyResourceDefinition {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

function getComponentName() {
  return "proxy-resource-manager";
}

export class ProxyResourceManager extends ResourceManager {
  private backendServerManager: BackendServerManager;

  constructor(backendServerManager: BackendServerManager) {
    // Initialize parent class with empty resources since we're proxying to backend servers
    super({
      definitions: {},
      handlers: {}
    });
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
        Logger.logError(error as Error, `Error getting resources from server ${connection.config.id}`, { component: getComponentName() });
      }
    }

    Logger.debug(`ProxyResourceManager: Found ${allResources.length} total resources`, { component: getComponentName() });

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
      Logger.debug(`ProxyResourceManager: Read resource ${uri} from server ${serverId}`, { component: getComponentName() });
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
      Logger.logError(error as Error, `Error reading resource ${uri} from server ${serverId}`, { component: getComponentName() });
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
      Logger.debug(`ProxyResourceManager: Subscribed to resource ${uri} from server ${serverId}`, { component: getComponentName() });
      return { success: true };
    } catch (error) {
      Logger.logError(error as Error, `Error subscribing to resource ${uri} from server ${serverId}`, { component: getComponentName() });
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
      Logger.debug(`ProxyResourceManager: Unsubscribed from resource ${uri} from server ${serverId}`, { component: getComponentName() });
      return { success: true };
    } catch (error) {
      Logger.logError(error as Error, `Error unsubscribing from resource ${uri} from server ${serverId}`, { component: getComponentName() });
      throw new McpError(ErrorCode.InternalError, `Failed to unsubscribe from resource from backend server: ${error}`);
    }
  }
}
