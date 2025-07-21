// HTTP Client Transport for MCP
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

export interface HttpClientTransportConfig {
  url: string;
  headers?: Record<string, string>;
  timeout?: number;
}

export class HttpClientTransport implements Transport {
  private config: HttpClientTransportConfig;
  private controller: AbortController | null = null;

  constructor(config: HttpClientTransportConfig) {
    this.config = config;
  }

  async start(): Promise<void> {
    // HTTP transport doesn't need persistent connection
    this.controller = new AbortController();
  }

  async send(message: any): Promise<any> {
    if (!this.controller) {
      throw new Error("HTTP transport not started");
    }

    const requestConfig: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
      },
      body: JSON.stringify(message),
      signal: this.controller.signal,
    };

    if (this.config.timeout) {
      const timeoutController = new AbortController();
      const timeoutId = setTimeout(() => timeoutController.abort(), this.config.timeout);
      
      try {
        const response = await fetch(this.config.url, {
          ...requestConfig,
          signal: timeoutController.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const responseData = await response.json();
        return responseData;
      } catch (error) {
        clearTimeout(timeoutId);
        throw error;
      }
    } else {
      const response = await fetch(this.config.url, requestConfig);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    }
  }

  async close(): Promise<void> {
    if (this.controller) {
      this.controller.abort();
      this.controller = null;
    }
  }

  // Required by Transport interface but not used for HTTP
  onclose?: () => void;
  onmessage?: (message: any) => void;
  onerror?: (error: Error) => void;
}
