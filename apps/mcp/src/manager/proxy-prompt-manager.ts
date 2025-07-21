import { Logger } from 'utils/logging';
import { BackendServerManager } from './backend-server-manager.js';
// Component name for logging
function getComponentName() {
  return "proxy-prompt-manager";
}

import { PromptManager } from './prompt-manager.js';
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

export class ProxyPromptManager extends PromptManager {
  private backendServerManager: BackendServerManager;

  constructor(backendServerManager: BackendServerManager) {
    // Initialize parent class with empty prompts since we're proxying to backend servers
    super({
      definitions: {},
      handlers: {}
    });
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
        Logger.logError(error as Error, `Error getting prompts from server ${connection.config.id}`, { component: getComponentName() });
      }
    }

    Logger.debug(`ProxyPromptManager: Found ${allPrompts.length} total prompts`, { component: getComponentName() });

    return {
      prompts: allPrompts,
    };
  }

  async getPrompt(request: { params: { name: string; arguments?: Record<string, string> } }): Promise<any> {
    const { name } = request.params;
    
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
      Logger.debug(`ProxyPromptManager: Got prompt ${name} from server ${serverId}`, { component: getComponentName() });
      return result;
    } catch (error) {
      Logger.logError(error as Error, `Error getting prompt ${name} from server ${serverId}`, { component: getComponentName() });
      throw new McpError(ErrorCode.InternalError, `Failed to get prompt from backend server: ${error}`);
    }
  }
}
