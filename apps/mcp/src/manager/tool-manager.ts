// ToolManager handles tool logic for McpServer
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import {
  ToolDefinition,
  ToolsetConfig,
  DynamicToolDiscoveryOptions,
  ToolCapability,
  AuthInfo,
} from "../types";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import Ajv from 'ajv';

export type ToolListResponse = {
  tools: (Omit<ToolDefinition, "inputSchema"> & {
    inputSchema: any;
  })[];
};

export class ToolManager {
  protected readonly tools: Map<string, ToolCapability> = new Map();
  protected enabledTools: Set<string> = new Set();
  protected enabledToolSubscriptions: Set<(tools: ToolListResponse) => void> =
    new Set();
  protected mcpServerName: string;
  private lastInfoOpts?: [
    { method: "tools/list"; params?: Record<string, unknown> },
    {
      signal: AbortSignal;
      sessionId: string;
      _meta: unknown;
      sendNotification: (type: string, payload: unknown) => void;
      sendRequest: () => Promise<unknown>;
      authInfo?: AuthInfo;
      requestId: string;
    }
  ];
  constructor(
    mcpServerName: string,
    protected toolsCapabilities: ToolCapability[],
    protected toolsetConfig: ToolsetConfig,
    protected dynamicToolDiscovery?: DynamicToolDiscoveryOptions
  ) {
    // replace -, sentence case and space with _ in mcpServerName
    this.mcpServerName = mcpServerName;

    this.toolsCapabilities.forEach((capability) => {
      this.tools.set(capability.definition.name, capability);
    });
    if (this.dynamicToolDiscovery?.enabled) {
      this.dynamicToolDiscovery.defaultEnabledToolsets?.forEach((toolName) => {
        if (this.tools.get(toolName)) {
          this.enabledTools.add(toolName);
        }
      });
    } else {
      this.tools.forEach((_, name) => {
        if (this.toolsetConfig.mode === "readWrite") {
          this.enabledTools.add(name);
        }
        if (
          this.toolsetConfig.mode === "readOnly" &&
          this.tools.get(name)?.definition.annotations?.readOnlyHint
        ) {
          this.enabledTools.add(name);
        }
      });
    }
    // Dynamic tool discovery logic
    if (this.dynamicToolDiscovery?.enabled) {
      const dynamicToolListName = `dynamic_tool_list`;
      const dynamicToolTriggerName = `dynamic_tool_trigger`;
      // Tool to list available/enabled tools
      this.tools.set(dynamicToolListName, {
        definition: {
          name: dynamicToolListName,
          description:
            "Lists all available and currently enabled tools for this MCP server instance. " +
            "Use this tool to discover which tools you can enable or disable dynamically. " +
            "The response contains two arrays: 'available' (all tools you can enable/disable) and 'enabled' (tools currently enabled and callable). " +
            "You should always call this tool before attempting to enable or disable any tool, to ensure you have the latest list of tool names and their current state. " +
            "Note: The dynamic_tool_list and dynamic_tool_trigger tools are not included in the available/enabled lists.",
          inputSchema: z.object({}),
          annotations: {
            title: `Dynamic Tool Discovery`,
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
          },
        },
        handler: ({}, req, opts) => {
          // Filter out the dynamic tools themselves from the lists
          const filterDynamic = (name: string) =>
            name !== dynamicToolListName && name !== dynamicToolTriggerName;
          // Helper to get tool info (name + description)
          const toolInfo = (name: string) => {
            const def = this.tools.get(name)?.definition;
            return {
              name: this.toExternalToolName(name),
              description: def
                ? this.toExternalToolDescription(def.description)
                : undefined,
            };
          };
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    available: Array.from(this.tools.keys())
                      .filter(filterDynamic)
                      .map(toolInfo),
                    enabled: Array.from(this.enabledTools)
                      .filter(filterDynamic)
                      .map(toolInfo),
                  },
                  null,
                  2
                ),
              },
            ],
          };
        },
      });
      this.enabledTools.add(dynamicToolListName);
      // Tool to enable/disable toolsets
      this.tools.set(dynamicToolTriggerName, {
        definition: {
          name: dynamicToolTriggerName,
          description:
            "Enables or disables one or more tools dynamically for this MCP server instance. " +
            "You must provide a list of toolsets, each with a 'name' (as returned by the dynamic_tool_list tool) and a 'trigger' (either 'enable' or 'disable'). " +
            "This tool should only be used after calling the dynamic_tool_list tool, to ensure you are using up-to-date tool names. " +
            "After enabling or disabling tools, the response will show the new state of available and enabled tools. " +
            "Note: The dynamic_tool_list and dynamic_tool_trigger tools cannot be enabled or disabled and are not accepted as valid tool names.",
          inputSchema: z.object({
            toolsets: z.array(
              z.object({
                name: z.string().refine(
                  (name) => {
                    const internal = this.toInternalToolName(name);
                    return (
                      internal !== dynamicToolListName &&
                      internal !== dynamicToolTriggerName &&
                      this.tools.has(internal) &&
                      this.tools.get(internal)?.definition.name === internal
                    );
                  },
                  {
                    message: "Invalid toolset name",
                  }
                ),
                trigger: z.enum(["enable", "disable"]),
              })
            ),
          }),
          annotations: {
            title: `Dynamic Tool Trigger`,
            readOnlyHint: false,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
          },
        },
        handler: async (params, req, opts) => {
          console.error(
            `Dynamic tool trigger called with params: ${JSON.stringify(
              params,
              null,
              2
            )}`
          );
          const { toolsets } = params;
          for (const { name, trigger } of toolsets) {
            const internal = this.toInternalToolName(name);
            if (
              internal === dynamicToolListName ||
              internal === dynamicToolTriggerName
            ) {
              throw new McpError(
                ErrorCode.InvalidParams,
                `Cannot enable/disable dynamic tools: ${name}`
              );
            }
            if (!this.tools.has(internal)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                `Unknown tool: ${name}`
              );
            }
            console.error(
              `Dynamic tool trigger: ${trigger} ${name} (${internal})`
            );
            if (trigger === "enable") {
              this.enabledTools.add(internal);
            } else if (trigger === "disable") {
              this.enabledTools.delete(internal);
            }
          }
          await this.notifyEnabledToolsChanged();
          // Filter out the dynamic tools themselves from the lists
          const filterDynamic = (name: string) =>
            name !== dynamicToolListName && name !== dynamicToolTriggerName;
          const toolInfo = (name: string) => {
            const def = this.tools.get(name)?.definition;
            return {
              name: this.toExternalToolName(name),
              description: def
                ? this.toExternalToolDescription(def.description)
                : undefined,
            };
          };
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    available: Array.from(this.tools.keys())
                      .filter(filterDynamic)
                      .map(toolInfo),
                    enabled: Array.from(this.enabledTools)
                      .filter(filterDynamic)
                      .map(toolInfo),
                  },
                  null,
                  2
                ),
              },
            ],
          };
        },
      });
      this.enabledTools.add(dynamicToolTriggerName);
    }
  }

  async isEnabledTool(name: string, authInfo?: AuthInfo): Promise<boolean> {
    const clientId = authInfo?.clientId || 'unknown-client';
    
    // Provide default authInfo if not provided
    const defaultAuthInfo: AuthInfo = authInfo || {
      token: '',
      clientId: 'unknown-client',
      scopes: [],
      extra: {}
    };
    
    console.error(
      `Checking if tool ${name} is enabled for ${clientId}. result: ${
        this.enabledTools.has(name) ? "enabled" : "not enabled"
      } and canBeEnabled: ${
        this.tools.get(name)?.meta?.canBeEnabled?.(defaultAuthInfo) !== false
          ? "true"
          : "false"
      } so : ${
        this.enabledTools.has(name) &&
        (await this.tools.get(name)?.meta?.canBeEnabled?.(defaultAuthInfo)) !== false
          ? "enabled"
          : "not enabled"
      }`
    );
    return (
      this.enabledTools.has(name) &&
      (await this.tools.get(name)?.meta?.canBeEnabled?.(defaultAuthInfo)) !== false
    );
  }

  async listTools(
    ...[req, opts]: [
      { method: "tools/list"; params: Record<string, unknown> },
      {
        signal: AbortSignal;
        sessionId: string;
        _meta: unknown;
        sendNotification: (type: string, payload: unknown) => void;
        sendRequest: () => Promise<unknown>;
        authInfo?: AuthInfo;
        requestId: string;
      }
    ]
  ): Promise<ToolListResponse> {
    this.lastInfoOpts = [req, opts];
    return {
      tools: (
        await Promise.all(
          Array.from(this.tools).map(async ([name, v]) => ({
            enabled: await this.isEnabledTool(name, opts.authInfo),
            d: [name, v] as const,
          }))
        )
      )
        .filter(({ enabled }) => enabled)
        .map(({ d }) => d)
        .map(([_, v]) => {
          // Validate inputSchema before processing
          if (!v.definition.inputSchema) {
            console.error(`Tool ${v.definition.name} has no inputSchema, using empty object schema`);
            return {
              ...v.definition,
              inputSchema: {
                type: "object",
                properties: {},
                additionalProperties: false,
              },
            };
          }

          try {
            return v.definition.inputSchema
              ? {
                  ...(v.definition.annotations
                    ? {
                        ...v.definition,
                        annotations: {
                          ...v.definition.annotations,
                          title: this.toExternalToolDescription(
                            v.definition.description
                          ),
                        },
                      }
                    : v.definition),
                  inputSchema: v.definition.inputSchema instanceof z.ZodObject
                    ? z.toJSONSchema(v.definition.inputSchema)
                    : v.definition.inputSchema,
                }
              : {
                  ...(v.definition.annotations
                    ? {
                        ...v.definition,
                        annotations: {
                          ...v.definition.annotations,
                          title: this.toExternalToolDescription(
                            v.definition.description
                          ),
                        },
                      }
                    : v.definition),
                  inputSchema: {
                    type: "object",
                    properties: {},
                    additionalProperties: false,
                  },
                };
          } catch (error) {
            console.error(`Error processing tool ${v.definition.name}:`, error);
            return {
              ...v.definition,
              inputSchema: {
                type: "object",
                properties: {},
                additionalProperties: false,
              },
            };
          }
        })
        .map((tool) => {
          return {
            ...tool,
            name: this.toExternalToolName(tool.name),
            description: this.toExternalToolDescription(tool.description),
          };
        }),
    };
  }
  async callTool(
    ...[req, opts]: [
      {
        method: "tools/call";
        params: {
          _meta?: Record<string, unknown>;
          name: string;
          arguments?: Record<string, unknown>;
        };
      },
      {
        signal: AbortSignal;
        sessionId: string;
        _meta: unknown;
        sendNotification: (type: string, payload: unknown) => void;
        sendRequest: () => Promise<unknown>;
        authInfo?: AuthInfo;
        requestId: string;
      }
    ]
  ) {
    const toolName = this.toInternalToolName(req.params.name);
    const toolCapability = this.tools.get(toolName);
    if (!toolCapability) {
      throw new McpError(
        ErrorCode.MethodNotFound,
        `Unknown tool: ${req.params.name}`
      );
    }
    if (!this.enabledTools.has(toolName)) {
      throw new McpError(
        ErrorCode.MethodNotFound,
        `Tool not enabled: ${req.params.name}`
      );
    }
    if (!req.params.arguments) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Invalid parameters: ${req.params.arguments}`
      );
    }
    
    const { inputSchema } = toolCapability.definition;
    
    let validatedData: any;
    
    // Check if inputSchema is a Zod schema or JSON schema
    if (inputSchema && typeof inputSchema.safeParse === 'function') {
      // It's a Zod schema
      const validationResult = inputSchema.safeParse(req.params.arguments);
      if (!validationResult.success) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Invalid parameters: ${validationResult.error}`
        );
      }
      validatedData = validationResult.data;
    } else if (inputSchema && typeof inputSchema === 'object' && 'type' in inputSchema) {
      // It's a JSON schema, use AJV for validation
      const ajv = new Ajv();
      const validate = ajv.compile(inputSchema);
      const valid = validate(req.params.arguments);
      
      if (!valid) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Invalid parameters: ${ajv.errorsText(validate.errors)}`
        );
      }
      validatedData = req.params.arguments;
    } else {
      throw new McpError(
        ErrorCode.InternalError,
        `Tool ${toolName} has invalid input schema - expected Zod schema or JSON schema`
      );
    }
    try {
      // Ensure required parameters have default values
      const reqWithDefaults = {
        ...req,
        params: {
          _meta: req.params._meta || {},
          name: req.params.name,
          arguments: req.params.arguments || {}
        }
      };
      return await toolCapability.handler(validatedData, reqWithDefaults, opts);
    } catch (err) {
      console.error("Tool handler error:", err);
      if (err instanceof McpError) {
        throw err;
      }
      throw new McpError(ErrorCode.InternalError, `Tool handler error: ${err}`);
    }
  }

  protected async notifyEnabledToolsChanged() {
    // Check if lastInfoOpts has been initialized
    if (!this.lastInfoOpts) {
      return; // Cannot notify without valid options
    }
    
    // Create a request with default params to satisfy the type requirement
    const req = {
      ...this.lastInfoOpts[0],
      params: this.lastInfoOpts[0].params || {}
    };
    const tools = await this.listTools(req, this.lastInfoOpts[1]);
    for (const callback of this.enabledToolSubscriptions) {
      callback(tools);
    }
  }

  private toInternalToolName(name: string): string {
    return name.replace(`${this.mcpServerName}__`, "");
  }
  private toExternalToolName(name: string): string {
    return `${this.mcpServerName}__${name}`;
  }
  private toExternalToolDescription(description: string): string {
    return `[${this.mcpServerName}] ${description}`;
  }

  onEnabledToolsChanged(callback: (tools: ToolListResponse) => void): void {
    this.enabledToolSubscriptions.add(callback);
  }
  offEnabledToolsChanged(callback: (tools: ToolListResponse) => void): void {
    this.enabledToolSubscriptions.delete(callback);
  }

  setMcpServerName(name: string) {
    this.mcpServerName = name;
    if (this.dynamicToolDiscovery?.enabled) {
      this.notifyEnabledToolsChanged();
    }
  }

  dynamicToolDiscoveryEnabled(): boolean {
    return this.dynamicToolDiscovery?.enabled ?? false;
  }

  hasTools() {
    return this.tools.size > 0;
  }

  addTool(toolCapability: ToolCapability) {
    this.tools.set(toolCapability.definition.name, toolCapability);
    
    // Enable the tool based on configuration
    if (this.toolsetConfig.mode === "readWrite" || 
        (toolCapability.definition.annotations?.readOnlyHint !== false)) {
      this.enabledTools.add(toolCapability.definition.name);
    }
  }
}
