import { RequestHandler } from "express";
import { 
  mcpAuthRouter, 
  mcpAuthMetadataRouter,
  AuthRouterOptions,
  AuthMetadataOptions 
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { ProxyOAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { BackendServerConfig } from "../types.js";

export interface OAuthServerInfo {
  serverId: string;
  config: BackendServerConfig;
  authorizationUrl: string;
  tokenUrl: string;
  revocationUrl?: string;
  metadataUrl?: string;
  needsOAuth: boolean;
  oauthDetected: boolean;
  lastOAuthError?: string;
}

export class OAuthProxyManager {
  private oauthServers: Map<string, OAuthServerInfo> = new Map();
  private oauthProviders: Map<string, ProxyOAuthServerProvider> = new Map();
  private _router?: RequestHandler;

  constructor(private baseUrl: string = 'http://localhost:3000') {
    this.initializeOAuthDetection();
  }

  /**
   * Initialize OAuth detection for all servers
   */
  private initializeOAuthDetection() {
    console.error("🔐 Initializing OAuth detection system...");
  }

  /**
   * Detect if a server needs OAuth authentication
   */
  async detectOAuthRequirement(serverId: string, config: BackendServerConfig, error?: string): Promise<boolean> {
    const existingInfo = this.oauthServers.get(serverId);
    
    // Check for OAuth indicators in error messages
    const needsOAuth = this.isOAuthError(error) || await this.checkOAuthMetadata(config);
    
    if (needsOAuth) {
      const oauthInfo: OAuthServerInfo = {
        serverId,
        config,
        authorizationUrl: this.buildOAuthUrl(config, '/oauth/authorize'),
        tokenUrl: this.buildOAuthUrl(config, '/oauth/token'),
        revocationUrl: this.buildOAuthUrl(config, '/oauth/revoke'),
        metadataUrl: this.buildOAuthUrl(config, '/.well-known/oauth-authorization-server'),
        needsOAuth: true,
        oauthDetected: true,
        lastOAuthError: error,
        ...existingInfo
      };
      
      this.oauthServers.set(serverId, oauthInfo);
      await this.setupOAuthProxy(oauthInfo);
      
      console.error(`🔐 OAuth detected for server ${serverId}: ${config.name}`);
      return true;
    }
    
    return false;
  }

  /**
   * Check if an error indicates OAuth is needed
   */
  private isOAuthError(error?: string): boolean {
    if (!error) return false;
    
    const oauthIndicators = [
      'authorization',
      'unauthorized',
      '401',
      'access_token',
      'oauth',
      'bearer',
      'authentication required',
      'missing required authorization header',
      'invalid_token',
      'token_expired'
    ];
    
    const errorLower = error.toLowerCase();
    return oauthIndicators.some(indicator => errorLower.includes(indicator));
  }

  /**
   * Check if server has OAuth metadata endpoints
   */
  private async checkOAuthMetadata(config: BackendServerConfig): Promise<boolean> {
    if (config.transportType !== 'http' && config.transportType !== 'sse') {
      return false;
    }
    
    try {
      const baseUrl = config.http?.url || config.sse?.url;
      if (!baseUrl) return false;
      
      const metadataUrl = this.buildOAuthUrl(config, '/.well-known/oauth-authorization-server');
      const response = await fetch(metadataUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.ok) {
        const metadata = await response.json();
        return metadata.authorization_endpoint && metadata.token_endpoint;
      }
    } catch (error) {
      // Metadata check failed, not necessarily an OAuth server
    }
    
    return false;
  }

  /**
   * Build OAuth URL based on server config
   */
  private buildOAuthUrl(config: BackendServerConfig, path: string): string {
    const baseUrl = config.http?.url || config.sse?.url || '';
    if (!baseUrl) return '';
    
    try {
      const url = new URL(baseUrl);
      url.pathname = path;
      return url.toString();
    } catch {
      return baseUrl + path;
    }
  }

  /**
   * Set up OAuth proxy for a specific server
   */
  private async setupOAuthProxy(oauthInfo: OAuthServerInfo): Promise<void> {
    try {
      const proxyProvider = new ProxyOAuthServerProvider({
        endpoints: {
          authorizationUrl: oauthInfo.authorizationUrl,
          tokenUrl: oauthInfo.tokenUrl,
          revocationUrl: oauthInfo.revocationUrl,
        },
        verifyAccessToken: async (token: string): Promise<AuthInfo> => {
          // For now, create a basic AuthInfo
          // In a real implementation, this would verify the token with the backend server
          return {
            token,
            clientId: 'mcp-proxy',
            scopes: ['read', 'write'],
            extra: { serverId: oauthInfo.serverId }
          };
        },
        getClient: async (clientId: string): Promise<OAuthClientInformationFull | undefined> => {
          // Return basic client info for now
          // In a real implementation, this would be configured per server
          return {
            client_id: clientId,
            client_name: `MCP Proxy Client for ${oauthInfo.serverId}`,
            redirect_uris: [`${this.baseUrl}/oauth/callback`],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic'
          };
        }
      });
      
      this.oauthProviders.set(oauthInfo.serverId, proxyProvider);
      console.error(`🔗 OAuth proxy configured for ${oauthInfo.serverId}`);
    } catch (error) {
      console.error(`❌ Failed to setup OAuth proxy for ${oauthInfo.serverId}:`, error);
    }
  }

  /**
   * Get OAuth router for Express app
   */
  getOAuthRouter(): RequestHandler {
    if (this._router) return this._router;
    
    // For now, create a basic OAuth router that handles multiple servers
    // In a full implementation, this would route to the appropriate provider based on the request
    const firstProvider = Array.from(this.oauthProviders.values())[0];
    
    if (!firstProvider) {
      // Return a no-op router if no OAuth providers are configured
      return (req, res, next) => next();
    }
    
    const routerOptions: AuthRouterOptions = {
      provider: firstProvider,
      issuerUrl: new URL(`${this.baseUrl}/oauth`),
      baseUrl: new URL(this.baseUrl),
      scopesSupported: ['read', 'write', 'admin'],
      resourceName: 'MCP Proxy Server'
    };
    
    this._router = mcpAuthRouter(routerOptions);
    return this._router;
  }

  /**
   * Get OAuth metadata router
   */
  getOAuthMetadataRouter(): RequestHandler {
    const oauthMetadata: OAuthMetadata = {
      issuer: `${this.baseUrl}/oauth`,
      authorization_endpoint: `${this.baseUrl}/oauth/authorize`,
      token_endpoint: `${this.baseUrl}/oauth/token`,
      jwks_uri: `${this.baseUrl}/oauth/jwks`,
      scopes_supported: ['read', 'write', 'admin'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256']
    };
    
    const metadataOptions: AuthMetadataOptions = {
      oauthMetadata,
      resourceServerUrl: new URL(this.baseUrl),
      scopesSupported: ['read', 'write', 'admin'],
      resourceName: 'MCP Proxy Server'
    };
    
    return mcpAuthMetadataRouter(metadataOptions);
  }

  /**
   * Get all servers that need OAuth
   */
  getOAuthServers(): OAuthServerInfo[] {
    return Array.from(this.oauthServers.values());
  }

  /**
   * Get OAuth server info by ID
   */
  getOAuthServerInfo(serverId: string): OAuthServerInfo | undefined {
    return this.oauthServers.get(serverId);
  }

  /**
   * Check if a server needs OAuth authentication
   */
  serverNeedsOAuth(serverId: string): boolean {
    const info = this.oauthServers.get(serverId);
    return info?.needsOAuth || false;
  }

  /**
   * Get authorization URL for a server
   */
  getAuthorizationUrl(serverId: string, redirectUri: string, scopes: string[] = ['read']): string | undefined {
    const info = this.oauthServers.get(serverId);
    if (!info) return undefined;
    
    const url = new URL(info.authorizationUrl);
    url.searchParams.set('client_id', 'mcp-proxy');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', scopes.join(' '));
    url.searchParams.set('state', `server:${serverId}`);
    
    return url.toString();
  }

  /**
   * Remove OAuth configuration for a server
   */
  removeOAuthServer(serverId: string): void {
    this.oauthServers.delete(serverId);
    this.oauthProviders.delete(serverId);
    this._router = undefined; // Force router recreation
  }

  /**
   * Get OAuth diagnostics
   */
  getOAuthDiagnostics() {
    const servers = Array.from(this.oauthServers.values());
    
    return {
      totalServers: servers.length,
      needsOAuth: servers.filter(s => s.needsOAuth).length,
      configured: servers.filter(s => this.oauthProviders.has(s.serverId)).length,
      errors: servers.filter(s => s.lastOAuthError).length,
      servers: servers.map(server => ({
        serverId: server.serverId,
        serverName: server.config.name,
        needsOAuth: server.needsOAuth,
        oauthDetected: server.oauthDetected,
        configured: this.oauthProviders.has(server.serverId),
        authorizationUrl: server.authorizationUrl,
        tokenUrl: server.tokenUrl,
        lastError: server.lastOAuthError
      }))
    };
  }
}