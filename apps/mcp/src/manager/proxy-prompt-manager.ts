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

export interface ProxyPromptDefinition {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

export class ProxyPromptManager {
  private backendServerManager: BackendServerManager;

  constructor(backendServerManager: BackendServerManager) {
    this.backendServerManager = backendServerManager;
  }

  async waitForInitialization(): Promise<void> {
    await this.backendServerManager.waitForInitialization();
  }

  hasPrompts(): boolean {
    // Always return true to enable prompt capabilities
    // We'll check at runtime if backend servers have prompts
    return true;
  }

  async listPrompts(request?: { params?: { cursor?: string } }): Promise<any> {
    // Aggregate prompts from all backend servers
    const allPrompts: ProxyPromptDefinition[] = [];
    
    const connections = this.backendServerManager.getAllConnections();
    
    for (const connection of connections) {
      try {
        if (connection.client && connection.prompts.size > 0) {
          // Get prompts from this backend server
          for (const [name, prompt] of connection.prompts) {
            // Prefix the name with server ID to avoid conflicts
            const prefixedPrompt = {
              ...prompt,
              name: `${connection.config.id}__${prompt.name}`,
              description: prompt.description ? `[${connection.config.id}] ${prompt.description}` : `[${connection.config.id}] ${prompt.name}`,
            };
            allPrompts.push(prefixedPrompt);
          }
        }
      } catch (error) {
        debugLog(`Error getting prompts from server ${connection.config.id}:`, error);
      }
    }

    debugLog(`ProxyPromptManager: Found ${allPrompts.length} total prompts`);

    return {
      prompts: allPrompts,
    };
  }

  async getPrompt(request: { params: { name: string; arguments?: Record<string, string> } }): Promise<any> {
    const name = request.params.name;
    
    // Check if this is a prefixed name from a backend server
    const match = name.match(/^([^_]+)__(.+)$/);
    if (!match) {
      throw new McpError(ErrorCode.InvalidRequest, `Invalid prompt name format: ${name}`);
    }

    const [, serverId, originalName] = match;
    const connection = this.backendServerManager.getServerConnection(serverId);
    
    if (!connection || !connection.client) {
      throw new McpError(ErrorCode.InvalidRequest, `Backend server not found or not connected: ${serverId}`);
    }

    try {
      // Delegate to the backend server
      const result = await connection.client.getPrompt({ 
        name: originalName, 
        arguments: request.params.arguments 
      });
      debugLog(`ProxyPromptManager: Got prompt ${name} from server ${serverId}`);
      return result;
    } catch (error) {
      debugLog(`Error getting prompt ${name} from server ${serverId}:`, error);
      throw new McpError(ErrorCode.InternalError, `Failed to get prompt from backend server: ${error}`);
    }
  }
}
