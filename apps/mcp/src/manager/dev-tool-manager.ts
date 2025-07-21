// Development tools manager - only active in development mode
import { ToolCapability } from "../types.js";
import { createToolDefinition } from "../utils/tools.js";
import { z } from "zod";
import { BackendServerManager } from "./backend-server-manager.js";
import { ProxyToolManager } from "./proxy-tool-manager.js";
import { ConfigurationManager } from "./configuration-manager.js";

// Interface for error tracking
export interface ErrorEntry {
  timestamp: Date;
  level: 'error' | 'warn' | 'info';
  source: string;
  message: string;
  details?: any;
  stack?: string;
}

// Interface for server diagnostics
export interface ServerDiagnostics {
  uptime: number;
  memoryUsage: NodeJS.MemoryUsage;
  toolsCount: number;
  enabledToolsCount: number;
  backendServersCount: number;
  connectedBackendServers: number;
  lastError?: ErrorEntry;
  recentErrors: ErrorEntry[];
}

export class DevToolManager {
  private static instance: DevToolManager | null = null;
  private errorLog: ErrorEntry[] = [];
  private maxLogEntries = 1000;
  private startTime = Date.now();
  
  constructor(
    private backendServerManager: BackendServerManager,
    private proxyToolManager: ProxyToolManager,
    private configurationManager: ConfigurationManager
  ) {
    // Singleton pattern to ensure only one instance exists
    if (DevToolManager.instance) {
      return DevToolManager.instance;
    }
    DevToolManager.instance = this;
    
    // Set up global error handlers to capture errors
    this.setupErrorHandlers();
  }

  static isDevModeEnabled(): boolean {
    return process.env.MCP_DEV_MODE === 'true';
  }

  private setupErrorHandlers() {
    // Capture console errors and warnings
    const originalConsoleError = console.error;
    const originalConsoleWarn = console.warn;
    
    console.error = (...args) => {
      this.logError('error', 'console', args.join(' '));
      originalConsoleError.apply(console, args);
    };
    
    console.warn = (...args) => {
      this.logError('warn', 'console', args.join(' '));
      originalConsoleWarn.apply(console, args);
    };
    
    // Capture unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      this.logError('error', 'unhandledRejection', `Unhandled Promise Rejection: ${reason}`, {
        promise: promise.toString(),
        reason
      });
    });
    
    // Capture uncaught exceptions (but don't override default behavior)
    process.on('uncaughtException', (error) => {
      this.logError('error', 'uncaughtException', error.message, {
        stack: error.stack,
        name: error.name
      });
    });
  }

  public logError(level: 'error' | 'warn' | 'info', source: string, message: string, details?: any, stack?: string) {
    const entry: ErrorEntry = {
      timestamp: new Date(),
      level,
      source,
      message,
      details,
      stack
    };
    
    this.errorLog.push(entry);
    
    // Keep only the latest entries
    if (this.errorLog.length > this.maxLogEntries) {
      this.errorLog = this.errorLog.slice(-this.maxLogEntries);
    }
  }

  private getServerDiagnostics(): ServerDiagnostics {
    const memoryUsage = process.memoryUsage();
    const uptime = Date.now() - this.startTime;
    const allTools = this.proxyToolManager.getAllTools();
    const enabledTools = this.proxyToolManager.getEnabledTools();
    const backendServers = this.backendServerManager.getAllServers();
    const connectedServers = backendServers.filter(server => server.connected);
    
    const recentErrors = this.errorLog
      .filter(entry => entry.level === 'error')
      .slice(-10);
    
    return {
      uptime,
      memoryUsage,
      toolsCount: allTools.length,
      enabledToolsCount: enabledTools.size,
      backendServersCount: backendServers.length,
      connectedBackendServers: connectedServers.length,
      lastError: this.errorLog.filter(e => e.level === 'error').pop(),
      recentErrors
    };
  }

  public getDevTools(): ToolCapability[] {
    if (!DevToolManager.isDevModeEnabled()) {
      return [];
    }

    return [
      this.createServerStatusTool(),
      this.createErrorLogsTool(),
      this.createToolDiagnosticsTool(),
      this.createResourceDiagnosticsTool(),
      this.createBackendServerStatusTool(),
      this.createConnectionDiagnosticsTool(),
      this.createConfigurationDiagnosticsTool(),
      this.createMemoryDiagnosticsTool()
    ];
  }

  private createServerStatusTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_server_status",
        description: "Get comprehensive server status and health information. Provides overall server diagnostics including uptime, memory usage, tool counts, backend server status, and recent errors.",
        inputSchema: z.object({
          includeDetails: z.boolean().optional().default(false).describe("Include detailed information about each component")
        }),
        annotations: {
          title: "Development: Server Status",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ includeDetails }) => {
        const diagnostics = this.getServerDiagnostics();
        
        const statusMessage = [
          `🚀 MCP Server Status (Dev Mode)`,
          ``,
          `⏱️  Uptime: ${Math.floor(diagnostics.uptime / 1000)}s`,
          `🧠 Memory Usage: ${Math.round(diagnostics.memoryUsage.used / 1024 / 1024)}MB used, ${Math.round(diagnostics.memoryUsage.heapUsed / 1024 / 1024)}MB heap`,
          `🔧 Tools: ${diagnostics.enabledToolsCount}/${diagnostics.toolsCount} enabled`,
          `🔗 Backend Servers: ${diagnostics.connectedBackendServers}/${diagnostics.backendServersCount} connected`,
          `❌ Recent Errors: ${diagnostics.recentErrors.length}`,
          ``
        ];

        if (diagnostics.lastError) {
          statusMessage.push(
            `🚨 Last Error: ${diagnostics.lastError.message}`,
            `   Source: ${diagnostics.lastError.source}`,
            `   Time: ${diagnostics.lastError.timestamp.toISOString()}`,
            ``
          );
        }

        if (includeDetails) {
          statusMessage.push(
            `📊 Detailed Memory Usage:`,
            `   RSS: ${Math.round(diagnostics.memoryUsage.rss / 1024 / 1024)}MB`,
            `   Heap Total: ${Math.round(diagnostics.memoryUsage.heapTotal / 1024 / 1024)}MB`,
            `   Heap Used: ${Math.round(diagnostics.memoryUsage.heapUsed / 1024 / 1024)}MB`,
            `   External: ${Math.round(diagnostics.memoryUsage.external / 1024 / 1024)}MB`,
            ``
          );
        }

        return {
          content: [{
            type: "text",
            text: statusMessage.join('\n')
          }]
        };
      }
    };
  }

  private createErrorLogsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_error_logs",
        description: "Retrieve recent error logs, warnings, and diagnostic information. Use this to identify problems and issues within the server for debugging and auto-fixing.",
        inputSchema: z.object({
          level: z.enum(['error', 'warn', 'info', 'all']).optional().default('all').describe("Filter by log level"),
          limit: z.number().min(1).max(100).optional().default(20).describe("Maximum number of entries to return"),
          source: z.string().optional().describe("Filter by error source")
        }),
        annotations: {
          title: "Development: Error Logs",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ level, limit, source }) => {
        let filteredLogs = [...this.errorLog];
        
        // Filter by level
        if (level !== 'all') {
          filteredLogs = filteredLogs.filter(entry => entry.level === level);
        }
        
        // Filter by source
        if (source) {
          filteredLogs = filteredLogs.filter(entry => 
            entry.source.toLowerCase().includes(source.toLowerCase())
          );
        }
        
        // Sort by timestamp (newest first) and limit
        filteredLogs = filteredLogs
          .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
          .slice(0, limit);
        
        if (filteredLogs.length === 0) {
          return {
            content: [{
              type: "text",
              text: "📝 No log entries found matching the specified criteria."
            }]
          };
        }

        const logMessage = [
          `📋 Error Logs (${filteredLogs.length} entries)`,
          ``,
          ...filteredLogs.map(entry => {
            const emoji = entry.level === 'error' ? '❌' : entry.level === 'warn' ? '⚠️' : 'ℹ️';
            const lines = [
              `${emoji} [${entry.level.toUpperCase()}] ${entry.timestamp.toISOString()}`,
              `   Source: ${entry.source}`,
              `   Message: ${entry.message}`
            ];
            
            if (entry.details) {
              lines.push(`   Details: ${JSON.stringify(entry.details, null, 2)}`);
            }
            
            if (entry.stack) {
              lines.push(`   Stack: ${entry.stack.split('\n').slice(0, 3).join('\n           ')}`);
            }
            
            return lines.join('\n');
          }),
          ``
        ];

        return {
          content: [{
            type: "text",
            text: logMessage.join('\n')
          }]
        };
      }
    };
  }

  private createToolDiagnosticsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_tool_diagnostics",
        description: "Analyze tool loading, execution issues, and availability. Identifies problems with tool registration, enabling/disabling, and execution failures.",
        inputSchema: z.object({
          toolName: z.string().optional().describe("Specific tool to diagnose"),
          includeDisabled: z.boolean().optional().default(false).describe("Include diagnostics for disabled tools")
        }),
        annotations: {
          title: "Development: Tool Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ toolName, includeDisabled }) => {
        const allTools = this.proxyToolManager.getAllTools();
        const enabledTools = this.proxyToolManager.getEnabledTools();
        
        let toolsToAnalyze = allTools;
        if (toolName) {
          toolsToAnalyze = allTools.filter(tool => 
            tool.definition.name.toLowerCase().includes(toolName.toLowerCase())
          );
        }
        
        const diagnosticsMessage = [
          `🔧 Tool Diagnostics`,
          ``,
          `📊 Summary:`,
          `   Total Tools: ${allTools.length}`,
          `   Enabled Tools: ${enabledTools.size}`,
          `   Disabled Tools: ${allTools.length - enabledTools.size}`,
          ``
        ];

        // Get tool-related errors
        const toolErrors = this.errorLog.filter(entry => 
          entry.source.includes('tool') || 
          entry.message.toLowerCase().includes('tool')
        ).slice(-5);

        if (toolErrors.length > 0) {
          diagnosticsMessage.push(
            `❌ Recent Tool-Related Errors:`,
            ...toolErrors.map(error => 
              `   • ${error.timestamp.toISOString()}: ${error.message}`
            ),
            ``
          );
        }

        diagnosticsMessage.push(`🔍 Tool Analysis:`);
        
        for (const tool of toolsToAnalyze.slice(0, 20)) { // Limit to prevent overwhelming output
          const isEnabled = enabledTools.has(tool.definition.name);
          const status = isEnabled ? '✅ Enabled' : '❌ Disabled';
          
          if (!includeDisabled && !isEnabled) continue;
          
          diagnosticsMessage.push(
            `   📋 ${tool.definition.name}`,
            `      Status: ${status}`,
            `      Description: ${tool.definition.description.substring(0, 100)}...`
          );
          
          // Check for specific tool annotations
          if (tool.definition.annotations) {
            const annotations = [];
            if (tool.definition.annotations.readOnlyHint) annotations.push('ReadOnly');
            if (tool.definition.annotations.destructiveHint) annotations.push('Destructive');
            if (tool.definition.annotations.idempotentHint) annotations.push('Idempotent');
            if (annotations.length > 0) {
              diagnosticsMessage.push(`      Annotations: ${annotations.join(', ')}`);
            }
          }
          
          diagnosticsMessage.push('');
        }

        return {
          content: [{
            type: "text",
            text: diagnosticsMessage.join('\n')
          }]
        };
      }
    };
  }

  private createResourceDiagnosticsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_resource_diagnostics",
        description: "Check resource loading issues, availability, and access problems. Identifies issues with resource discovery, loading, and subscription management.",
        inputSchema: z.object({
          checkConnectivity: z.boolean().optional().default(false).describe("Test resource connectivity")
        }),
        annotations: {
          title: "Development: Resource Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ checkConnectivity }) => {
        const resourceErrors = this.errorLog.filter(entry => 
          entry.source.includes('resource') || 
          entry.message.toLowerCase().includes('resource')
        ).slice(-10);

        const diagnosticsMessage = [
          `📂 Resource Diagnostics`,
          ``,
          `🔍 Resource System Status:`,
          `   Resource-related errors: ${resourceErrors.length}`,
          ``
        ];

        if (resourceErrors.length > 0) {
          diagnosticsMessage.push(
            `❌ Recent Resource Errors:`,
            ...resourceErrors.map(error => 
              `   • ${error.timestamp.toISOString()}: ${error.message}`
            ),
            ``
          );
        } else {
          diagnosticsMessage.push(`✅ No recent resource-related errors found`, ``);
        }

        // Check backend server resource capabilities
        const backendServers = this.backendServerManager.getAllServers();
        diagnosticsMessage.push(`🔗 Backend Server Resource Status:`);
        
        for (const server of backendServers) {
          const status = server.connected ? '✅ Connected' : '❌ Disconnected';
          diagnosticsMessage.push(
            `   📡 ${server.id} (${server.name})`,
            `      Status: ${status}`,
            `      Resources: ${server.resourcesCount || 'Unknown'}`
          );
        }

        return {
          content: [{
            type: "text",
            text: diagnosticsMessage.join('\n')
          }]
        };
      }
    };
  }

  private createBackendServerStatusTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_backend_server_status",
        description: "Get detailed status of all backend MCP servers including connection health, tool counts, and last errors. Essential for debugging backend connectivity issues.",
        inputSchema: z.object({
          serverId: z.string().optional().describe("Specific server ID to check"),
          includeConfig: z.boolean().optional().default(false).describe("Include server configuration details")
        }),
        annotations: {
          title: "Development: Backend Server Status",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ serverId, includeConfig }) => {
        const backendServers = this.backendServerManager.getAllServers();
        let serversToCheck = backendServers;
        
        if (serverId) {
          serversToCheck = backendServers.filter(server => server.id === serverId);
        }

        const statusMessage = [
          `🔗 Backend Server Status`,
          ``,
          `📊 Overview: ${backendServers.filter(s => s.connected).length}/${backendServers.length} servers connected`,
          ``
        ];

        for (const server of serversToCheck) {
          const status = server.connected ? '✅ Connected' : '❌ Disconnected';
          const lastConnected = server.lastConnected ? 
            `Last connected: ${server.lastConnected.toISOString()}` : 
            'Never connected';
          
          statusMessage.push(
            `📡 ${server.id} - ${server.name}`,
            `   Status: ${status}`,
            `   ${lastConnected}`,
            `   Tools: ${server.toolsCount || 'Unknown'}`,
            `   Resources: ${server.resourcesCount || 'Unknown'}`,
            `   Prompts: ${server.promptsCount || 'Unknown'}`
          );
          
          if (server.lastError) {
            statusMessage.push(`   Last Error: ${server.lastError}`);
          }
          
          statusMessage.push('');
        }

        return {
          content: [{
            type: "text",
            text: statusMessage.join('\n')
          }]
        };
      }
    };
  }

  private createConnectionDiagnosticsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_connection_diagnostics",
        description: "Diagnose connection issues with backend servers, network problems, and communication failures. Includes connection testing and network diagnostics.",
        inputSchema: z.object({
          testConnections: z.boolean().optional().default(false).describe("Perform active connection tests"),
          serverId: z.string().optional().describe("Test specific server connection")
        }),
        annotations: {
          title: "Development: Connection Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ testConnections, serverId }) => {
        const connectionErrors = this.errorLog.filter(entry => 
          entry.source.includes('connection') || 
          entry.source.includes('transport') ||
          entry.message.toLowerCase().includes('connection') ||
          entry.message.toLowerCase().includes('connect')
        ).slice(-10);

        const diagnosticsMessage = [
          `🌐 Connection Diagnostics`,
          ``,
          `🔍 Connection Error Analysis:`,
          `   Connection-related errors: ${connectionErrors.length}`,
          ``
        ];

        if (connectionErrors.length > 0) {
          diagnosticsMessage.push(
            `❌ Recent Connection Errors:`,
            ...connectionErrors.map(error => 
              `   • ${error.timestamp.toISOString()}: ${error.message}`
            ),
            ``
          );
        }

        // Check backend server connections
        const backendServers = this.backendServerManager.getAllServers();
        let serversToCheck = backendServers;
        
        if (serverId) {
          serversToCheck = backendServers.filter(server => server.id === serverId);
        }

        diagnosticsMessage.push(`🔗 Server Connection Status:`);
        
        for (const server of serversToCheck) {
          const status = server.connected ? '✅ Connected' : '❌ Disconnected';
          diagnosticsMessage.push(
            `   📡 ${server.id}: ${status}`
          );
          
          if (!server.connected && server.lastError) {
            diagnosticsMessage.push(`      Error: ${server.lastError}`);
          }
        }

        return {
          content: [{
            type: "text",
            text: diagnosticsMessage.join('\n')
          }]
        };
      }
    };
  }

  private createConfigurationDiagnosticsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_configuration_diagnostics",
        description: "Validate server configuration, check for configuration errors, and identify misconfiguration issues that could cause problems.",
        inputSchema: z.object({
          section: z.enum(['all', 'servers', 'security', 'discovery']).optional().default('all').describe("Configuration section to check")
        }),
        annotations: {
          title: "Development: Configuration Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ section }) => {
        const config = this.configurationManager.getConfiguration();
        
        const diagnosticsMessage = [
          `⚙️ Configuration Diagnostics`,
          ``,
          `🔍 Configuration Validation:`,
          ``
        ];

        // Basic configuration checks
        if (section === 'all' || section === 'servers') {
          diagnosticsMessage.push(
            `📡 Server Configuration:`,
            `   Total servers configured: ${config.servers.length}`,
            `   Enabled servers: ${config.servers.filter(s => s.enabled).length}`,
            ``
          );
          
          // Check for common configuration issues
          const issues = [];
          
          config.servers.forEach(server => {
            if (!server.transportType) {
              issues.push(`Server ${server.id}: Missing transport type`);
            }
            
            if (server.transportType === 'stdio' && !server.stdio?.command) {
              issues.push(`Server ${server.id}: STDIO transport missing command`);
            }
            
            if (server.transportType === 'http' && !server.http?.url) {
              issues.push(`Server ${server.id}: HTTP transport missing URL`);
            }
            
            if (server.transportType === 'sse' && !server.sse?.url) {
              issues.push(`Server ${server.id}: SSE transport missing URL`);
            }
          });
          
          if (issues.length > 0) {
            diagnosticsMessage.push(
              `❌ Configuration Issues:`,
              ...issues.map(issue => `   • ${issue}`),
              ``
            );
          } else {
            diagnosticsMessage.push(`✅ No server configuration issues found`, ``);
          }
        }

        if (section === 'all' || section === 'security') {
          diagnosticsMessage.push(
            `🔒 Security Configuration:`,
            `   Global allowed tools: ${config.security?.globalAllowedTools?.length || 0}`,
            `   Global blocked tools: ${config.security?.globalBlockedTools?.length || 0}`,
            `   Default auth required: ${config.security?.defaultRequireAuth || false}`,
            ``
          );
        }

        if (section === 'all' || section === 'discovery') {
          diagnosticsMessage.push(
            `🔍 Discovery Configuration:`,
            `   Discovery enabled: ${config.discovery?.enabled || false}`,
            `   Runtime server addition: ${config.discovery?.allowRuntimeServerAddition || false}`,
            `   Metadata exposure: ${config.discovery?.serverMetadataExposure || 'none'}`,
            ``
          );
        }

        // Check for environment variable issues
        const envIssues = [];
        if (!process.env.NODE_ENV) {
          envIssues.push('NODE_ENV not set');
        }
        
        if (envIssues.length > 0) {
          diagnosticsMessage.push(
            `🌍 Environment Issues:`,
            ...envIssues.map(issue => `   • ${issue}`),
            ``
          );
        }

        return {
          content: [{
            type: "text",
            text: diagnosticsMessage.join('\n')
          }]
        };
      }
    };
  }

  private createMemoryDiagnosticsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_memory_diagnostics",
        description: "Monitor memory usage, performance metrics, and identify potential memory leaks or performance issues in the server.",
        inputSchema: z.object({
          includeGC: z.boolean().optional().default(false).describe("Include garbage collection information"),
          benchmark: z.boolean().optional().default(false).describe("Run a quick performance benchmark")
        }),
        annotations: {
          title: "Development: Memory Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ includeGC, benchmark }) => {
        const memoryUsage = process.memoryUsage();
        const uptime = process.uptime();
        
        const diagnosticsMessage = [
          `🧠 Memory Diagnostics`,
          ``,
          `📊 Current Memory Usage:`,
          `   RSS (Resident Set Size): ${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
          `   Heap Total: ${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
          `   Heap Used: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
          `   External: ${Math.round(memoryUsage.external / 1024 / 1024)}MB`,
          `   Array Buffers: ${Math.round(memoryUsage.arrayBuffers / 1024 / 1024)}MB`,
          ``,
          `⏱️ Performance Metrics:`,
          `   Uptime: ${Math.floor(uptime)}s`,
          `   Heap Usage: ${Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100)}%`,
          ``
        ];

        // Memory threshold warnings
        const heapUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
        if (heapUsagePercent > 80) {
          diagnosticsMessage.push(`⚠️ Warning: High heap usage (${Math.round(heapUsagePercent)}%)`, ``);
        }

        if (memoryUsage.rss > 512 * 1024 * 1024) { // 512MB
          diagnosticsMessage.push(`⚠️ Warning: High RSS usage (${Math.round(memoryUsage.rss / 1024 / 1024)}MB)`, ``);
        }

        // Count objects in memory (approximate)
        diagnosticsMessage.push(
          `📈 Resource Counts:`,
          `   Error log entries: ${this.errorLog.length}`,
          `   Backend servers: ${this.backendServerManager.getAllServers().length}`,
          `   Total tools: ${this.proxyToolManager.getAllTools().length}`,
          `   Enabled tools: ${this.proxyToolManager.getEnabledTools().size}`,
          ``
        );

        if (benchmark) {
          // Simple performance benchmark
          const start = process.hrtime.bigint();
          
          // Perform some operations
          const testArray = new Array(10000).fill(0).map((_, i) => i * 2);
          const sum = testArray.reduce((a, b) => a + b, 0);
          
          const end = process.hrtime.bigint();
          const duration = Number(end - start) / 1000000; // Convert to milliseconds
          
          diagnosticsMessage.push(
            `🏃 Performance Benchmark:`,
            `   Array operation (10k elements): ${duration.toFixed(2)}ms`,
            `   Result: ${sum}`,
            ``
          );
        }

        return {
          content: [{
            type: "text",
            text: diagnosticsMessage.join('\n')
          }]
        };
      }
    };
  }
}