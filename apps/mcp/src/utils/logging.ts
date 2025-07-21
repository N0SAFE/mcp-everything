import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";

export type LogLevel = "debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency";

export interface LogMetadata {
  component?: string;
  serverId?: string;
  toolName?: string;
  operation?: string;
  error?: Error | string;
  [key: string]: any;
}

/**
 * Centralized logging utility for MCP proxy server
 * Uses MCP server's sendLoggingMessage when available, falls back to console when not
 */
export class Logger {
  private static mcpServer: Server | null = null;

  /**
   * Set the MCP server instance for logging
   * Should be called once the server is available
   */
  static setMcpServer(server: Server) {
    this.mcpServer = server;
  }

  /**
   * Send a log message with the appropriate level
   */
  static log(level: LogLevel, message: string, metadata?: LogMetadata) {
    try {
        if (!this.mcpServer) {
            throw new McpError(1001, "MCP server not set for logging");
        }
        // Use MCP server's logging mechanism
        this.mcpServer.sendLoggingMessage({
          level,
          data: metadata ? { message, ...metadata } : message,
        });
    } catch {}
  }

  /**
   * Convenience methods for different log levels
   */
  static debug(message: string, metadata?: LogMetadata) {
    this.log("debug", message, metadata);
  }

  static info(message: string, metadata?: LogMetadata) {
    this.log("info", message, metadata);
  }

  static notice(message: string, metadata?: LogMetadata) {
    this.log("notice", message, metadata);
  }

  static warning(message: string, metadata?: LogMetadata) {
    this.log("warning", message, metadata);
  }

  static error(message: string, metadata?: LogMetadata) {
    this.log("error", message, metadata);
  }

  static critical(message: string, metadata?: LogMetadata) {
    this.log("critical", message, metadata);
  }

  /**
   * Helper to log errors with proper context
   */
  static logError(error: Error | string, context?: string, metadata?: LogMetadata) {
    const errorMessage = error instanceof Error ? error.message : error;
    const contextMessage = context ? `${context}: ${errorMessage}` : errorMessage;
    
    this.error(contextMessage, {
      ...metadata,
      error: error instanceof Error ? error.stack : error,
    });
  }

  /**
   * Helper to log operation start/completion
   */
  static logOperation(operation: string, status: "start" | "complete" | "failed", metadata?: LogMetadata) {
    const message = `${operation} ${status}`;
    const level = status === "failed" ? "error" : "info";
    
    this.log(level, message, {
      ...metadata,
      operation,
      status,
    });
  }

  /**
   * Helper to log server-related events
   */
  static logServer(serverId: string, event: string, status?: "success" | "failed", metadata?: LogMetadata) {
    const message = `Server ${serverId}: ${event}`;
    const level = status === "failed" ? "error" : "info";
    
    this.log(level, message, {
      ...metadata,
      serverId,
      event,
      status,
    });
  }

  /**
   * Helper to log tool-related events
   */
  static logTool(toolName: string, event: string, status?: "success" | "failed", metadata?: LogMetadata) {
    const message = `Tool ${toolName}: ${event}`;
    const level = status === "failed" ? "error" : "debug";
    
    this.log(level, message, {
      ...metadata,
      toolName,
      event,
      status,
    });
  }
}
