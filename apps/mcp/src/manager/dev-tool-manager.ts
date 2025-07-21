// Development tools manager - only active in development mode
import { ToolCapability } from "../types.js";
import { createToolDefinition } from "../utils/tools.js";
import { z } from "zod";
import { BackendServerManager, FailedServerAttempt } from "./backend-server-manager.js";
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
  category?: string;
  impact?: 'low' | 'medium' | 'high' | 'critical';
}

// Interface for performance metrics
export interface PerformanceMetrics {
  timestamp: Date;
  memoryUsage: NodeJS.MemoryUsage;
  cpuUsage?: NodeJS.CpuUsage;
  eventLoopDelay?: number;
  requestCount?: number;
}

// Interface for server diagnostics
export interface ServerDiagnostics {
  uptime: number;
  memoryUsage: NodeJS.MemoryUsage;
  toolsCount: number;
  enabledToolsCount: number;
  backendServersCount: number;
  connectedBackendServers: number;
  failedBackendServers: number;
  disabledBackendServers: number;
  lastError?: ErrorEntry;
  recentErrors: ErrorEntry[];
  errorsByCategory: Record<string, number>;
  performanceMetrics?: PerformanceMetrics[];
}

export class DevToolManager {
  private static instance: DevToolManager | null = null;
  private errorLog: ErrorEntry[] = [];
  private performanceHistory: PerformanceMetrics[] = [];
  private maxLogEntries = 1000;
  private maxPerformanceEntries = 100;
  private startTime = Date.now();
  private performanceTimer?: NodeJS.Timeout;
  
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
    
    // Start performance monitoring
    this.startPerformanceMonitoring();
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
    // Categorize the error
    const category = this.categorizeError(source, message);
    const impact = this.assessErrorImpact(level, source, message);
    
    const entry: ErrorEntry = {
      timestamp: new Date(),
      level,
      source,
      message,
      details,
      stack,
      category,
      impact
    };
    
    this.errorLog.push(entry);
    
    // Keep only the latest entries
    if (this.errorLog.length > this.maxLogEntries) {
      this.errorLog = this.errorLog.slice(-this.maxLogEntries);
    }
  }

  private categorizeError(source: string, message: string): string {
    const lowerSource = source.toLowerCase();
    const lowerMessage = message.toLowerCase();
    
    if (lowerSource.includes('connection') || lowerMessage.includes('connection')) return 'connection';
    if (lowerSource.includes('tool') || lowerMessage.includes('tool')) return 'tool';
    if (lowerSource.includes('resource') || lowerMessage.includes('resource')) return 'resource';
    if (lowerSource.includes('config') || lowerMessage.includes('config')) return 'configuration';
    if (lowerSource.includes('memory') || lowerMessage.includes('memory')) return 'memory';
    if (lowerSource.includes('transport') || lowerMessage.includes('transport')) return 'transport';
    if (lowerSource.includes('server') || lowerMessage.includes('server')) return 'server';
    return 'general';
  }

  private assessErrorImpact(level: 'error' | 'warn' | 'info', source: string, message: string): 'low' | 'medium' | 'high' | 'critical' {
    if (level === 'error') {
      if (source.includes('uncaughtException') || message.includes('crash')) return 'critical';
      if (source.includes('connection') || message.includes('failed to connect')) return 'high';
      return 'medium';
    }
    if (level === 'warn') return 'low';
    return 'low';
  }

  private startPerformanceMonitoring() {
    // Collect performance metrics every 30 seconds
    this.performanceTimer = setInterval(() => {
      this.collectPerformanceMetrics();
    }, 30000);
  }

  private collectPerformanceMetrics() {
    const metrics: PerformanceMetrics = {
      timestamp: new Date(),
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
    };
    
    this.performanceHistory.push(metrics);
    
    // Keep only recent metrics
    if (this.performanceHistory.length > this.maxPerformanceEntries) {
      this.performanceHistory = this.performanceHistory.slice(-this.maxPerformanceEntries);
    }
  }

  private getServerDiagnostics(): ServerDiagnostics {
    const memoryUsage = process.memoryUsage();
    const uptime = Date.now() - this.startTime;
    const allTools = this.proxyToolManager.getAllTools();
    const enabledTools = this.proxyToolManager.getEnabledTools();
    const backendConnections = this.backendServerManager.getAllConnections();
    const failedServers = this.backendServerManager.getFailedServers();
    const allServerStatuses = this.backendServerManager.getAllServerStatuses();
    
    const connectedServers = backendConnections.filter(conn => conn.status.connected);
    const disabledServers = allServerStatuses.filter(status => 
      'attemptCount' in status && status.config.enabled === false
    );
    
    const recentErrors = this.errorLog
      .filter(entry => entry.level === 'error')
      .slice(-10);
    
    // Categorize errors
    const errorsByCategory: Record<string, number> = {};
    this.errorLog.forEach(error => {
      const category = error.category || 'general';
      errorsByCategory[category] = (errorsByCategory[category] || 0) + 1;
    });
    
    return {
      uptime,
      memoryUsage,
      toolsCount: allTools.length,
      enabledToolsCount: enabledTools.size,
      backendServersCount: allServerStatuses.length,
      connectedBackendServers: connectedServers.length,
      failedBackendServers: failedServers.length,
      disabledBackendServers: disabledServers.length,
      lastError: this.errorLog.filter(e => e.level === 'error').pop(),
      recentErrors,
      errorsByCategory,
      performanceMetrics: this.performanceHistory.slice(-10)
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
      this.createMemoryDiagnosticsTool(),
      this.createEnvironmentDiagnosticsTool()
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
          `🧠 Memory Usage: ${Math.round(diagnostics.memoryUsage.heapUsed / 1024 / 1024)}MB heap, ${Math.round(diagnostics.memoryUsage.rss / 1024 / 1024)}MB RSS`,
          `🔧 Tools: ${diagnostics.enabledToolsCount}/${diagnostics.toolsCount} enabled`,
          `🔗 Backend Servers: ${diagnostics.connectedBackendServers}/${diagnostics.backendServersCount} total`,
          `   ✅ Connected: ${diagnostics.connectedBackendServers}`,
          `   ❌ Failed: ${diagnostics.failedBackendServers}`,
          `   🚫 Disabled: ${diagnostics.disabledBackendServers}`,
          `❌ Recent Errors: ${diagnostics.recentErrors.length}`,
          ``
        ];

        // Show error patterns
        if (Object.keys(diagnostics.errorsByCategory).length > 0) {
          statusMessage.push(`📊 Error Categories:`);
          Object.entries(diagnostics.errorsByCategory)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .forEach(([category, count]) => {
              statusMessage.push(`   ${category}: ${count} errors`);
            });
          statusMessage.push(``);
        }

        if (diagnostics.lastError) {
          const impact = diagnostics.lastError.impact || 'unknown';
          const impactEmoji = impact === 'critical' ? '🚨' : impact === 'high' ? '⚠️' : impact === 'medium' ? '📋' : 'ℹ️';
          statusMessage.push(
            `${impactEmoji} Last Error (${impact} impact):`,
            `   Message: ${diagnostics.lastError.message}`,
            `   Source: ${diagnostics.lastError.source}`,
            `   Category: ${diagnostics.lastError.category || 'unknown'}`,
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

          // Show performance trends if available
          if (diagnostics.performanceMetrics && diagnostics.performanceMetrics.length > 1) {
            const latest = diagnostics.performanceMetrics[diagnostics.performanceMetrics.length - 1];
            const previous = diagnostics.performanceMetrics[diagnostics.performanceMetrics.length - 2];
            const memoryTrend = latest.memoryUsage.heapUsed - previous.memoryUsage.heapUsed;
            const trendEmoji = memoryTrend > 0 ? '📈' : memoryTrend < 0 ? '📉' : '➡️';
            
            statusMessage.push(
              `📈 Performance Trends:`,
              `   ${trendEmoji} Memory trend: ${memoryTrend > 0 ? '+' : ''}${Math.round(memoryTrend / 1024 / 1024)}MB`,
              `   📊 Metrics history: ${diagnostics.performanceMetrics.length} samples`,
              ``
            );
          }
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
        description: "Retrieve and analyze error logs, warnings, and diagnostic information with advanced filtering and pattern analysis. Provides insights into error trends, categories, and impact assessment for debugging and auto-fixing.",
        inputSchema: z.object({
          level: z.enum(['error', 'warn', 'info', 'all']).optional().default('all').describe("Filter by log level"),
          limit: z.number().min(1).max(100).optional().default(20).describe("Maximum number of entries to return"),
          source: z.string().optional().describe("Filter by error source"),
          category: z.string().optional().describe("Filter by error category (connection, tool, resource, etc.)"),
          impact: z.enum(['low', 'medium', 'high', 'critical']).optional().describe("Filter by error impact level"),
          since: z.string().optional().describe("Show errors since timestamp (ISO format)"),
          analysis: z.boolean().optional().default(false).describe("Include detailed error pattern analysis")
        }),
        annotations: {
          title: "Development: Error Logs",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ level, limit, source, category, impact, since, analysis }) => {
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
        
        // Filter by category
        if (category) {
          filteredLogs = filteredLogs.filter(entry => 
            entry.category?.toLowerCase().includes(category.toLowerCase())
          );
        }
        
        // Filter by impact
        if (impact) {
          filteredLogs = filteredLogs.filter(entry => entry.impact === impact);
        }
        
        // Filter by timestamp
        if (since) {
          const sinceDate = new Date(since);
          filteredLogs = filteredLogs.filter(entry => entry.timestamp >= sinceDate);
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
          `📋 Error Logs Analysis (${filteredLogs.length} entries)`,
          ``
        ];

        // Add analysis if requested
        if (analysis) {
          const categoryCount: Record<string, number> = {};
          const impactCount: Record<string, number> = {};
          const sourceCount: Record<string, number> = {};
          
          filteredLogs.forEach(entry => {
            const cat = entry.category || 'unknown';
            const imp = entry.impact || 'unknown';
            categoryCount[cat] = (categoryCount[cat] || 0) + 1;
            impactCount[imp] = (impactCount[imp] || 0) + 1;
            sourceCount[entry.source] = (sourceCount[entry.source] || 0) + 1;
          });
          
          logMessage.push(
            `📊 Pattern Analysis:`,
            ``,
            `🏷️ Top Categories:`,
            ...Object.entries(categoryCount)
              .sort(([,a], [,b]) => b - a)
              .slice(0, 5)
              .map(([cat, count]) => `   ${cat}: ${count} errors`),
            ``,
            `🎯 Impact Distribution:`,
            ...Object.entries(impactCount)
              .sort(([,a], [,b]) => b - a)
              .map(([imp, count]) => `   ${imp}: ${count} errors`),
            ``,
            `📍 Top Error Sources:`,
            ...Object.entries(sourceCount)
              .sort(([,a], [,b]) => b - a)
              .slice(0, 5)
              .map(([src, count]) => `   ${src}: ${count} errors`),
            ``,
            `📝 Detailed Log Entries:`,
            ``
          );
        }

        logMessage.push(
          ...filteredLogs.map(entry => {
            const levelEmoji = entry.level === 'error' ? '❌' : entry.level === 'warn' ? '⚠️' : 'ℹ️';
            const impactEmoji = entry.impact === 'critical' ? '🚨' : 
                              entry.impact === 'high' ? '⚠️' : 
                              entry.impact === 'medium' ? '📋' : 'ℹ️';
            
            const lines = [
              `${levelEmoji} [${entry.level.toUpperCase()}] ${entry.timestamp.toISOString()}`,
              `   Source: ${entry.source}`,
              `   Message: ${entry.message}`
            ];
            
            if (entry.category) {
              lines.push(`   Category: ${entry.category}`);
            }
            
            if (entry.impact) {
              lines.push(`   Impact: ${impactEmoji} ${entry.impact}`);
            }
            
            if (entry.details) {
              lines.push(`   Details: ${JSON.stringify(entry.details, null, 2)}`);
            }
            
            if (entry.stack) {
              lines.push(`   Stack: ${entry.stack.split('\n').slice(0, 3).join('\n           ')}`);
            }
            
            return lines.join('\n');
          }),
          ``
        );

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
        const backendConnections = this.backendServerManager.getAllConnections();
        diagnosticsMessage.push(`🔗 Backend Server Resource Status:`);
        
        for (const connection of backendConnections) {
          const status = connection.status.connected ? '✅ Connected' : '❌ Disconnected';
          diagnosticsMessage.push(
            `   📡 ${connection.config.id} (${connection.config.name})`,
            `      Status: ${status}`,
            `      Resources: ${connection.status.resourcesCount || 'Unknown'}`
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
        description: "Get detailed status of all backend MCP servers including connection health, tool counts, and last errors. Essential for debugging backend connectivity issues with auto-fix suggestions.",
        inputSchema: z.object({
          serverId: z.string().optional().describe("Specific server ID to check"),
          includeConfig: z.boolean().optional().default(false).describe("Include server configuration details"),
          includeFixes: z.boolean().optional().default(true).describe("Include auto-fix suggestions for failed servers")
        }),
        annotations: {
          title: "Development: Backend Server Status",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ serverId, includeConfig, includeFixes }) => {
        const backendConnections = this.backendServerManager.getAllConnections();
        const failedServers = this.backendServerManager.getFailedServers();
        const allServerStatuses = this.backendServerManager.getAllServerStatuses();
        
        let serversToCheck = allServerStatuses;
        
        if (serverId) {
          serversToCheck = allServerStatuses.filter(server => 
            ('config' in server && server.config.id === serverId) ||
            ('status' in server && server.status.id === serverId)
          );
        }

        const statusMessage = [
          `🔗 Backend Server Status`,
          ``,
          `📊 Overview: ${backendConnections.length} connected, ${failedServers.length} failed, ${allServerStatuses.length} total`,
          ``
        ];

        // Group servers by status
        const connectedServers = serversToCheck.filter(server => 
          'client' in server && server.status.connected
        );
        const failedServersList = serversToCheck.filter(server => 
          'attemptCount' in server && server.config.enabled !== false
        );
        const disabledServers = serversToCheck.filter(server => 
          'attemptCount' in server && server.config.enabled === false
        );

        // Show connected servers
        if (connectedServers.length > 0) {
          statusMessage.push(`✅ Connected Servers (${connectedServers.length}):`);
          for (const server of connectedServers) {
            if ('client' in server) {
              const lastConnected = server.status.lastConnected ? 
                `Connected: ${server.status.lastConnected.toISOString()}` : 
                'Recently connected';
              
              statusMessage.push(
                `   📡 ${server.config.id} - ${server.config.name}`,
                `      Status: ✅ Connected`,
                `      ${lastConnected}`,
                `      Tools: ${server.status.toolsCount || 0}`,
                `      Resources: ${server.status.resourcesCount || 0}`,
                `      Prompts: ${server.status.promptsCount || 0}`
              );
              
              if (server.config.description) {
                statusMessage.push(`      Description: ${server.config.description}`);
              }
              
              statusMessage.push('');
            }
          }
        }

        // Show failed servers with enhanced diagnostics
        if (failedServersList.length > 0) {
          statusMessage.push(`❌ Failed Servers (${failedServersList.length}):`);
          for (const server of failedServersList) {
            if ('attemptCount' in server) {
              const timeSinceFirstFailure = Date.now() - server.firstFailure.getTime();
              const timeSinceLastAttempt = Date.now() - server.lastAttempt.getTime();
              
              statusMessage.push(
                `   📡 ${server.config.id} - ${server.config.name}`,
                `      Status: ❌ Failed (${server.attemptCount} attempts)`,
                `      First failure: ${Math.floor(timeSinceFirstFailure / 1000)}s ago`,
                `      Last attempt: ${Math.floor(timeSinceLastAttempt / 1000)}s ago`,
                `      Error: ${server.status.lastError || 'Unknown error'}`
              );
              
              if (server.config.description) {
                statusMessage.push(`      Description: ${server.config.description}`);
              }
              
              // Show transport details for debugging
              statusMessage.push(`      Transport: ${server.config.transportType}`);
              if (server.config.transportType === 'stdio' && server.config.stdio) {
                statusMessage.push(`      Command: ${server.config.stdio.command}`);
                if (server.config.stdio.args && server.config.stdio.args.length > 0) {
                  statusMessage.push(`      Args: ${server.config.stdio.args.join(' ')}`);
                }
              } else if (server.config.transportType === 'http' && server.config.http) {
                statusMessage.push(`      URL: ${server.config.http.url}`);
              } else if (server.config.transportType === 'sse' && server.config.sse) {
                statusMessage.push(`      URL: ${server.config.sse.url}`);
              }
              
              // Add auto-fix suggestions
              if (includeFixes) {
                const fixes = this.generateFixSuggestions(server);
                if (fixes.length > 0) {
                  statusMessage.push(`      🔧 Suggested Fixes:`);
                  fixes.forEach(fix => statusMessage.push(`         • ${fix}`));
                }
              }
              
              statusMessage.push('');
            }
          }
        }

        // Show disabled servers
        if (disabledServers.length > 0) {
          statusMessage.push(`🚫 Disabled Servers (${disabledServers.length}):`);
          for (const server of disabledServers) {
            if ('attemptCount' in server) {
              statusMessage.push(
                `   📡 ${server.config.id} - ${server.config.name}`,
                `      Status: 🚫 Disabled`,
                `      Transport: ${server.config.transportType}`
              );
              
              if (server.config.description) {
                statusMessage.push(`      Description: ${server.config.description}`);
              }
              
              statusMessage.push('');
            }
          }
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

  private generateFixSuggestions(server: FailedServerAttempt): string[] {
    const fixes: string[] = [];
    const error = server.status.lastError || '';
    const errorLower = error.toLowerCase();
    
    // HTTP 401 errors (GitHub token issues)
    if (errorLower.includes('401') || errorLower.includes('authorization')) {
      fixes.push('Set GITHUB_TOKEN environment variable with a valid GitHub Personal Access Token');
      fixes.push('Ensure the token has appropriate scopes (repo, read:user, etc.)');
      fixes.push('Check if the token has expired or been revoked');
    }
    
    // Connection closed errors (stdio transport issues)
    if (errorLower.includes('connection closed') || errorLower.includes('econnreset')) {
      if (server.config.transportType === 'stdio') {
        fixes.push('Check if the command is installed: ' + (server.config.stdio?.command || 'unknown'));
        if (server.config.stdio?.command === 'npx') {
          fixes.push('Ensure npm/npx is installed and working: npm --version');
          fixes.push('Try manually running: npx ' + (server.config.stdio?.args?.join(' ') || ''));
          fixes.push('Check network connectivity for package downloads');
        }
        if (server.config.stdio?.command === 'uvx') {
          fixes.push('Ensure uvx (uv) is installed: uvx --version');
          fixes.push('Try manually running: uvx ' + (server.config.stdio?.args?.join(' ') || ''));
        }
      }
    }
    
    // Network/timeout errors
    if (errorLower.includes('timeout') || errorLower.includes('network')) {
      fixes.push('Check internet connectivity');
      fixes.push('Verify firewall settings are not blocking the connection');
      fixes.push('Try increasing timeout values in configuration');
    }
    
    // Permission errors
    if (errorLower.includes('permission') || errorLower.includes('access denied')) {
      fixes.push('Check file/directory permissions');
      fixes.push('Ensure the process has necessary access rights');
      fixes.push('Try running with appropriate user permissions');
    }
    
    // Command not found errors
    if (errorLower.includes('command not found') || errorLower.includes('enoent')) {
      if (server.config.stdio?.command) {
        fixes.push(`Install the missing command: ${server.config.stdio.command}`);
        fixes.push(`Add the command to your PATH environment variable`);
        fixes.push(`Verify installation with: which ${server.config.stdio.command}`);
      }
    }
    
    // Generic fallback suggestions
    if (fixes.length === 0) {
      fixes.push('Check server logs for more detailed error information');
      fixes.push('Verify server configuration is correct');
      fixes.push('Test the server independently to ensure it works');
      
      if (server.config.transportType === 'stdio') {
        fixes.push('Try running the command manually to test it works');
      } else if (server.config.transportType === 'http') {
        fixes.push('Test the HTTP endpoint manually with curl or browser');
      } else if (server.config.transportType === 'sse') {
        fixes.push('Test the SSE endpoint manually');
      }
    }
    
    return fixes;
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
        const backendConnections = this.backendServerManager.getAllConnections();
        let connectionsToCheck = backendConnections;
        
        if (serverId) {
          connectionsToCheck = backendConnections.filter(conn => conn.config.id === serverId);
        }

        diagnosticsMessage.push(`🔗 Server Connection Status:`);
        
        for (const connection of connectionsToCheck) {
          const status = connection.status.connected ? '✅ Connected' : '❌ Disconnected';
          diagnosticsMessage.push(
            `   📡 ${connection.config.id}: ${status}`
          );
          
          if (!connection.status.connected && connection.status.lastError) {
            diagnosticsMessage.push(`      Error: ${connection.status.lastError}`);
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
          const issues: string[] = [];
          
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
        description: "Advanced memory usage monitoring, performance analysis, and leak detection. Includes historical trends, memory pressure analysis, and performance optimization recommendations.",
        inputSchema: z.object({
          includeGC: z.boolean().optional().default(false).describe("Include garbage collection information"),
          benchmark: z.boolean().optional().default(false).describe("Run a quick performance benchmark"),
          analysis: z.boolean().optional().default(true).describe("Include detailed memory analysis and recommendations"),
          history: z.boolean().optional().default(false).describe("Show memory usage history and trends")
        }),
        annotations: {
          title: "Development: Memory Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ includeGC, benchmark, analysis, history }) => {
        const memoryUsage = process.memoryUsage();
        const uptime = process.uptime();
        
        const diagnosticsMessage = [
          `🧠 Advanced Memory Diagnostics`,
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

        // Memory threshold warnings and analysis
        const heapUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
        const warnings = [];
        
        if (heapUsagePercent > 80) {
          warnings.push(`⚠️ Critical: High heap usage (${Math.round(heapUsagePercent)}%) - Consider memory optimization`);
        } else if (heapUsagePercent > 60) {
          warnings.push(`⚠️ Warning: Elevated heap usage (${Math.round(heapUsagePercent)}%) - Monitor closely`);
        }

        if (memoryUsage.rss > 512 * 1024 * 1024) { // 512MB
          warnings.push(`⚠️ Warning: High RSS usage (${Math.round(memoryUsage.rss / 1024 / 1024)}MB) - Check for memory leaks`);
        }

        if (memoryUsage.external > 100 * 1024 * 1024) { // 100MB
          warnings.push(`⚠️ Info: High external memory usage (${Math.round(memoryUsage.external / 1024 / 1024)}MB) - Buffers/streams in use`);
        }

        if (warnings.length > 0) {
          diagnosticsMessage.push(`🚨 Memory Alerts:`, ...warnings.map(w => `   ${w}`), ``);
        }

        // Historical analysis
        if (history && this.performanceHistory.length > 1) {
          diagnosticsMessage.push(`📈 Memory History Analysis:`);
          
          const recentMetrics = this.performanceHistory.slice(-10);
          const memoryTrend = this.calculateMemoryTrend(recentMetrics);
          const growthRate = this.calculateMemoryGrowthRate(recentMetrics);
          
          const trendEmoji = memoryTrend > 0 ? '📈' : memoryTrend < 0 ? '📉' : '➡️';
          diagnosticsMessage.push(
            `   ${trendEmoji} Memory trend: ${memoryTrend > 0 ? '+' : ''}${Math.round(memoryTrend / 1024 / 1024)}MB over ${recentMetrics.length} samples`,
            `   📊 Growth rate: ${growthRate.toFixed(2)}MB/minute`,
            `   📊 Samples collected: ${this.performanceHistory.length}`,
            ``
          );

          // Memory leak detection
          if (growthRate > 5) { // Growing more than 5MB per minute
            diagnosticsMessage.push(
              `🚨 Potential Memory Leak Detected:`,
              `   📈 Rapid memory growth: ${growthRate.toFixed(2)}MB/minute`,
              `   🔍 Recommendation: Investigate object retention and cleanup`,
              ``
            );
          }
        }

        // Advanced analysis
        if (analysis) {
          diagnosticsMessage.push(
            `🔍 Advanced Analysis:`,
            ``
          );

          // Memory efficiency analysis
          const efficiency = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
          if (efficiency < 30) {
            diagnosticsMessage.push(`   ✅ Good: Low heap fragmentation (${efficiency.toFixed(1)}% used)`);
          } else if (efficiency > 80) {
            diagnosticsMessage.push(`   ⚠️ Poor: High heap pressure (${efficiency.toFixed(1)}% used)`);
          } else {
            diagnosticsMessage.push(`   📊 Normal: Moderate heap usage (${efficiency.toFixed(1)}% used)`);
          }

          // External memory analysis
          const externalRatio = (memoryUsage.external / memoryUsage.rss) * 100;
          if (externalRatio > 20) {
            diagnosticsMessage.push(`   📊 High external memory ratio (${externalRatio.toFixed(1)}%) - Large buffers in use`);
          }

          // Provide recommendations
          diagnosticsMessage.push(
            ``,
            `💡 Performance Recommendations:`
          );

          if (heapUsagePercent > 70) {
            diagnosticsMessage.push(`   • Consider implementing object pooling or caching optimizations`);
            diagnosticsMessage.push(`   • Review data structures for memory efficiency`);
          }

          if (this.errorLog.length > 500) {
            diagnosticsMessage.push(`   • Error log has ${this.errorLog.length} entries - consider log rotation`);
          }

          const toolCount = this.proxyToolManager.getAllTools().length;
          if (toolCount > 100) {
            diagnosticsMessage.push(`   • High tool count (${toolCount}) - consider lazy loading`);
          }

          diagnosticsMessage.push(``);
        }

        // Count objects in memory (approximate)
        diagnosticsMessage.push(
          `📈 Resource Counts:`,
          `   Error log entries: ${this.errorLog.length}`,
          `   Performance samples: ${this.performanceHistory.length}`,
          `   Backend servers: ${this.backendServerManager.getAllConnections().length}`,
          `   Failed servers: ${this.backendServerManager.getFailedServers().length}`,
          `   Total tools: ${this.proxyToolManager.getAllTools().length}`,
          `   Enabled tools: ${this.proxyToolManager.getEnabledTools().size}`,
          ``
        );

        if (benchmark) {
          // Enhanced performance benchmark
          const start = process.hrtime.bigint();
          
          // Perform various operations
          const testArray = new Array(10000).fill(0).map((_, i) => i * 2);
          const sum = testArray.reduce((a, b) => a + b, 0);
          
          // Test object creation and cleanup
          const objects = [];
          for (let i = 0; i < 1000; i++) {
            objects.push({ id: i, data: new Array(100).fill(i) });
          }
          
          const end = process.hrtime.bigint();
          const duration = Number(end - start) / 1000000; // Convert to milliseconds
          
          diagnosticsMessage.push(
            `🏃 Performance Benchmark:`,
            `   Array operations (10k elements): ${duration.toFixed(2)}ms`,
            `   Object creation (1k objects): Included in total`,
            `   Benchmark result: ${sum}`,
            `   Memory after benchmark: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
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

  private createEnvironmentDiagnosticsTool(): ToolCapability {
    return {
      definition: createToolDefinition({
        name: "dev_environment_diagnostics",
        description: "Check environment setup, dependencies, and system requirements for backend servers. Helps diagnose missing dependencies and configuration issues.",
        inputSchema: z.object({
          checkCommands: z.boolean().optional().default(true).describe("Check if required commands are available"),
          checkEnvVars: z.boolean().optional().default(true).describe("Check required environment variables"),
          testConnectivity: z.boolean().optional().default(false).describe("Test network connectivity to external services")
        }),
        annotations: {
          title: "Development: Environment Diagnostics",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      }),
      handler: async ({ checkCommands, checkEnvVars, testConnectivity }) => {
        const diagnosticsMessage = [
          `🌍 Environment Diagnostics`,
          ``,
        ];

        if (checkEnvVars) {
          diagnosticsMessage.push(`🔑 Environment Variables:`);
          
          const requiredEnvVars = [
            { name: 'GITHUB_TOKEN', description: 'Required for GitHub MCP server authentication', optional: false },
            { name: 'BRAVE_API_KEY', description: 'Required for Brave Search server', optional: true },
            { name: 'MCP_DEV_MODE', description: 'Enables development tools', optional: true },
            { name: 'NODE_ENV', description: 'Node.js environment setting', optional: true },
            { name: 'MEMORY_FILE_PATH', description: 'Path for memory server storage', optional: true }
          ];

          let envIssuesFound = 0;
          for (const envVar of requiredEnvVars) {
            const value = process.env[envVar.name];
            const status = value ? '✅ Set' : (envVar.optional ? '⚠️ Missing (optional)' : '❌ Missing (required)');
            
            diagnosticsMessage.push(`   ${envVar.name}: ${status}`);
            if (value && envVar.name.includes('TOKEN')) {
              // Don't show full token, just indicate length
              diagnosticsMessage.push(`     Value: ${value.substring(0, 8)}... (${value.length} chars)`);
            } else if (value && envVar.name !== 'GITHUB_TOKEN') {
              diagnosticsMessage.push(`     Value: ${value}`);
            }
            diagnosticsMessage.push(`     Description: ${envVar.description}`);
            
            if (!value && !envVar.optional) {
              envIssuesFound++;
              diagnosticsMessage.push(`     🔧 Fix: Set this environment variable`);
            }
            
            diagnosticsMessage.push(``);
          }

          if (envIssuesFound > 0) {
            diagnosticsMessage.push(`⚠️ Found ${envIssuesFound} missing required environment variables`, ``);
          }
        }

        if (checkCommands) {
          diagnosticsMessage.push(`🔧 Command Dependencies:`);
          
          const requiredCommands = [
            { name: 'node', description: 'Node.js runtime', test: '--version' },
            { name: 'npm', description: 'Node package manager', test: '--version' },
            { name: 'npx', description: 'Node package executor', test: '--version' },
            { name: 'uvx', description: 'UV package executor (for Python packages)', test: '--version' },
            { name: 'python', description: 'Python runtime (for uvx packages)', test: '--version' },
            { name: 'bun', description: 'Bun runtime (current environment)', test: '--version' }
          ];

          for (const cmd of requiredCommands) {
            try {
              // Try to check if command exists (simplified check)
              const hasCommand = await this.checkCommandExists(cmd.name);
              const status = hasCommand ? '✅ Available' : '❌ Missing';
              
              diagnosticsMessage.push(`   ${cmd.name}: ${status}`);
              diagnosticsMessage.push(`     Description: ${cmd.description}`);
              
              if (!hasCommand) {
                diagnosticsMessage.push(`     🔧 Fix: Install ${cmd.name} on your system`);
              }
              
              diagnosticsMessage.push(``);
            } catch (error) {
              diagnosticsMessage.push(`   ${cmd.name}: ❓ Unknown (${error})`);
              diagnosticsMessage.push(`     Description: ${cmd.description}`);
              diagnosticsMessage.push(``);
            }
          }
        }

        if (testConnectivity) {
          diagnosticsMessage.push(`🌐 Network Connectivity:`);
          
          const endpoints = [
            { url: 'https://registry.npmjs.org', name: 'NPM Registry', description: 'Required for npx package downloads' },
            { url: 'https://api.githubcopilot.com', name: 'GitHub Copilot API', description: 'Required for GitHub MCP server' },
            { url: 'https://mcp.deepwiki.com', name: 'DeepWiki MCP', description: 'Required for DeepWiki server' }
          ];

          for (const endpoint of endpoints) {
            try {
              const start = Date.now();
              const response = await fetch(endpoint.url, { 
                method: 'HEAD', 
                signal: AbortSignal.timeout(5000) 
              });
              const duration = Date.now() - start;
              const status = response.ok ? `✅ Reachable (${duration}ms)` : `⚠️ Reachable but HTTP ${response.status}`;
              
              diagnosticsMessage.push(`   ${endpoint.name}: ${status}`);
              diagnosticsMessage.push(`     URL: ${endpoint.url}`);
              diagnosticsMessage.push(`     Description: ${endpoint.description}`);
              diagnosticsMessage.push(``);
            } catch (error) {
              diagnosticsMessage.push(`   ${endpoint.name}: ❌ Unreachable`);
              diagnosticsMessage.push(`     URL: ${endpoint.url}`);
              diagnosticsMessage.push(`     Error: ${error instanceof Error ? error.message : String(error)}`);
              diagnosticsMessage.push(`     Description: ${endpoint.description}`);
              diagnosticsMessage.push(`     🔧 Fix: Check internet connection and firewall settings`);
              diagnosticsMessage.push(``);
            }
          }
        }

        // System information
        diagnosticsMessage.push(
          `💻 System Information:`,
          `   Platform: ${process.platform}`,
          `   Architecture: ${process.arch}`,
          `   Node.js Version: ${process.version}`,
          `   Working Directory: ${process.cwd()}`,
          `   Process ID: ${process.pid}`,
          `   Memory Usage: ${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
          ``
        );

        // Auto-fix recommendations summary
        diagnosticsMessage.push(
          `🔧 Quick Fix Commands:`,
          `   Install missing dependencies: npm install -g npx`,
          `   Set GitHub token: export GITHUB_TOKEN=your_token_here`,
          `   Enable dev mode: export MCP_DEV_MODE=true`,
          `   Install UV for Python packages: curl -LsSf https://astral.sh/uv/install.sh | sh`,
          ``
        );

        return {
          content: [{
            type: "text",
            text: diagnosticsMessage.join('\n')
          }]
        };
      }
    };
  }

  private async checkCommandExists(command: string): Promise<boolean> {
    try {
      // Use which command on Unix-like systems, where on Windows
      const whichCommand = process.platform === 'win32' ? 'where' : 'which';
      const { spawn } = await import('child_process');
      
      return new Promise((resolve) => {
        const proc = spawn(whichCommand, [command], { stdio: 'ignore' });
        proc.on('close', (code) => resolve(code === 0));
        proc.on('error', () => resolve(false));
        
        // Timeout after 2 seconds
        setTimeout(() => {
          proc.kill();
          resolve(false);
        }, 2000);
      });
    } catch {
      return false;
    }
  }

  private calculateMemoryTrend(metrics: PerformanceMetrics[]): number {
    if (metrics.length < 2) return 0;
    const latest = metrics[metrics.length - 1];
    const first = metrics[0];
    return latest.memoryUsage.heapUsed - first.memoryUsage.heapUsed;
  }

  private calculateMemoryGrowthRate(metrics: PerformanceMetrics[]): number {
    if (metrics.length < 2) return 0;
    const latest = metrics[metrics.length - 1];
    const first = metrics[0];
    const timeDiff = (latest.timestamp.getTime() - first.timestamp.getTime()) / (1000 * 60); // minutes
    const memDiff = (latest.memoryUsage.heapUsed - first.memoryUsage.heapUsed) / (1024 * 1024); // MB
    return timeDiff > 0 ? memDiff / timeDiff : 0;
  }
}