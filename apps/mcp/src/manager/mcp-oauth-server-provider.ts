/**
 * MCP OAuth Server Provider - Implements OAuth for MCP servers according to specification
 * https://modelcontextprotocol.io/specification/draft/basic/authorization
 */

import { Response } from "express";
import { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { BackendServerConfig } from "../types.js";

export interface McpOAuthServerInfo {
  serverId: string;
  config: BackendServerConfig;
  provider: OAuthServerProvider;
  clientStore: OAuthRegisteredClientsStore;
  authorizationUrl?: string;
  tokenUrl?: string;
  revocationUrl?: string;
  metadataUrl?: string;
  needsOAuth?: boolean;
  oauthDetected?: boolean;
  lastOAuthError?: string;
}

// Simple in-memory client store implementation
class InMemoryClientStore implements OAuthRegisteredClientsStore {
  private clients: Map<string, OAuthClientInformationFull> = new Map();

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async registerClient(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): Promise<OAuthClientInformationFull> {
    const fullClient: OAuthClientInformationFull = {
      ...client,
      client_id: `mcp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      client_id_issued_at: Math.floor(Date.now() / 1000)
    };
    this.clients.set(fullClient.client_id, fullClient);
    return fullClient;
  }

  async storeClient(client: OAuthClientInformationFull): Promise<void> {
    this.clients.set(client.client_id, client);
  }
}

/**
 * OAuth Server Provider that handles OAuth flows for backend MCP servers
 */
export class McpOAuthServerProvider implements OAuthServerProvider {
  private oauthServers: Map<string, McpOAuthServerInfo> = new Map();
  private _clientsStore: OAuthRegisteredClientsStore;
  private baseUrl: string;

  constructor(baseUrl: string = 'http://localhost:3001') {
    this.baseUrl = baseUrl;
    this._clientsStore = new InMemoryClientStore();
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  /**
   * Register an OAuth-enabled backend server
   */
  async registerServer(serverId: string, config: BackendServerConfig): Promise<void> {
    console.error(`🔐 Registering OAuth server: ${serverId} (${config.name})`);
    
    // Create a dedicated client store for this server
    const clientStore = new InMemoryClientStore();
    
    // For GitHub MCP server, register appropriate OAuth client
    if (this.isGitHubMcpServer(config)) {
      await this.registerGitHubClient(clientStore, serverId);
    } else {
      // Register a generic client for other servers
      await this.registerGenericClient(clientStore, serverId);
    }

    // Create server provider that delegates to appropriate OAuth endpoints
    const serverProvider = this.createServerProvider(serverId, config);
    
    const serverInfo: McpOAuthServerInfo = {
      serverId,
      config,
      provider: serverProvider,
      clientStore,
      authorizationUrl: this.isGitHubMcpServer(config) ? 
        'https://github.com/login/oauth/authorize' : undefined,
      tokenUrl: this.isGitHubMcpServer(config) ? 
        'https://github.com/login/oauth/access_token' : undefined,
      metadataUrl: this.isGitHubMcpServer(config) ? 
        'https://github.com/.well-known/oauth-authorization-server' : undefined,
      needsOAuth: true,
      oauthDetected: true
    };
    
    this.oauthServers.set(serverId, serverInfo);
    console.error(`✅ OAuth server registered: ${serverId}`);
  }

  /**
   * Check if a server needs OAuth authentication
   */
  serverNeedsOAuth(serverId: string): boolean {
    return this.oauthServers.has(serverId);
  }

  /**
   * Get OAuth server info for a specific server
   */
  getOAuthServerInfo(serverId: string): McpOAuthServerInfo | undefined {
    return this.oauthServers.get(serverId);
  }

  private async registerGitHubClient(clientStore: OAuthRegisteredClientsStore, serverId: string): Promise<void> {
    const clientInfo: OAuthClientInformationFull = {
      client_id: `github-mcp-${serverId}`,
      client_name: `GitHub MCP Client for ${serverId}`,
      redirect_uris: [
        `${this.baseUrl}/oauth/callback`,
        `${this.baseUrl}/oauth/${serverId}/callback`
      ],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'repo read:user read:org'
    };
    
    await (clientStore as InMemoryClientStore).storeClient(clientInfo);
  }

  private async registerGenericClient(clientStore: OAuthRegisteredClientsStore, serverId: string): Promise<void> {
    const clientInfo: OAuthClientInformationFull = {
      client_id: `mcp-${serverId}`,
      client_name: `MCP Client for ${serverId}`,
      redirect_uris: [
        `${this.baseUrl}/oauth/callback`,
        `${this.baseUrl}/oauth/${serverId}/callback`
      ],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic'
    };
    
    await (clientStore as InMemoryClientStore).storeClient(clientInfo);
  }

  private createServerProvider(serverId: string, config: BackendServerConfig): OAuthServerProvider {
    if (this.isGitHubMcpServer(config)) {
      return this.createGitHubProvider(serverId, config);
    } else {
      return this.createGenericProvider(serverId, config);
    }
  }

  private createGitHubProvider(serverId: string, config: BackendServerConfig): OAuthServerProvider {
    const clientStore = this.oauthServers.get(serverId)?.clientStore || this._clientsStore;
    let storedCodeChallenge: string = '';
    
    return {
      get clientsStore() {
        return clientStore;
      },
      
      async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        // Store the code challenge for later verification
        storedCodeChallenge = params.codeChallenge;
        
        // Redirect to GitHub OAuth authorization endpoint
        const authUrl = new URL('https://github.com/login/oauth/authorize');
        authUrl.searchParams.set('client_id', process.env.GITHUB_CLIENT_ID || client.client_id);
        authUrl.searchParams.set('redirect_uri', params.redirectUri);
        authUrl.searchParams.set('scope', params.scopes?.join(' ') || 'repo read:user read:org');
        authUrl.searchParams.set('state', params.state || '');
        authUrl.searchParams.set('response_type', 'code');
        
        // Redirect to GitHub OAuth
        res.redirect(authUrl.toString());
      },
      
      async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        return storedCodeChallenge; // Return the stored challenge
      },
      
      async exchangeAuthorizationCode(
        client: OAuthClientInformationFull, 
        authorizationCode: string, 
        codeVerifier?: string, 
        redirectUri?: string, 
        resource?: URL
      ): Promise<OAuthTokens> {
        // Exchange code with GitHub
        const response = await fetch('https://github.com/login/oauth/access_token', {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            client_id: process.env.GITHUB_CLIENT_ID || client.client_id,
            client_secret: process.env.GITHUB_CLIENT_SECRET || '',
            code: authorizationCode,
            redirect_uri: redirectUri || ''
          })
        });
        
        if (!response.ok) {
          throw new Error(`Failed to exchange code: ${response.statusText}`);
        }
        
        const tokens = await response.json();
        
        return {
          access_token: tokens.access_token,
          token_type: tokens.token_type || 'bearer',
          scope: tokens.scope,
          refresh_token: tokens.refresh_token,
          expires_in: tokens.expires_in
        };
      },
      
      async exchangeRefreshToken(
        client: OAuthClientInformationFull, 
        refreshToken: string, 
        scopes?: string[], 
        resource?: URL
      ): Promise<OAuthTokens> {
        // GitHub doesn't support refresh tokens in the same way, so return the existing token
        throw new Error('GitHub OAuth refresh tokens not supported');
      },
      
      async verifyAccessToken(token: string): Promise<AuthInfo> {
        // Verify token with GitHub API
        const response = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });
        
        if (!response.ok) {
          throw new Error('Invalid or expired token');
        }
        
        const user = await response.json();
        
        return {
          token,
          clientId: `mcp-github-${serverId}`, // Use a constructed client ID
          scopes: ['repo', 'read:user', 'read:org'],
          extra: {
            serverId,
            provider: 'github',
            user: user.login,
            userId: user.id
          }
        };
      },
      
      async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        // GitHub token revocation
        const response = await fetch(`https://api.github.com/applications/${client.client_id}/token`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Basic ${Buffer.from(`${client.client_id}:${process.env.GITHUB_CLIENT_SECRET || ''}`).toString('base64')}`,
            'Accept': 'application/vnd.github.v3+json'
          },
          body: JSON.stringify({
            access_token: request.token
          })
        });
        
        if (!response.ok && response.status !== 404) {
          throw new Error(`Failed to revoke token: ${response.statusText}`);
        }
      }
    };
  }

  private createGenericProvider(serverId: string, config: BackendServerConfig): OAuthServerProvider {
    const clientStore = this.oauthServers.get(serverId)?.clientStore || this._clientsStore;
    let storedCodeChallenge: string = '';
    
    return {
      get clientsStore() {
        return clientStore;
      },
      
      async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        // Store the code challenge for later verification
        storedCodeChallenge = params.codeChallenge;
        
        // For generic servers, we need to redirect to their OAuth endpoint
        const baseUrl = config.http?.url || config.sse?.url;
        if (!baseUrl) {
          throw new Error('No base URL available for OAuth redirect');
        }
        
        const authUrl = new URL('/oauth/authorize', baseUrl);
        authUrl.searchParams.set('client_id', client.client_id);
        authUrl.searchParams.set('redirect_uri', params.redirectUri);
        authUrl.searchParams.set('scope', params.scopes?.join(' ') || 'read write');
        authUrl.searchParams.set('state', params.state || '');
        authUrl.searchParams.set('response_type', 'code');
        
        res.redirect(authUrl.toString());
      },
      
      async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        return storedCodeChallenge;
      },
      
      async exchangeAuthorizationCode(
        client: OAuthClientInformationFull, 
        authorizationCode: string, 
        codeVerifier?: string, 
        redirectUri?: string, 
        resource?: URL
      ): Promise<OAuthTokens> {
        const baseUrl = config.http?.url || config.sse?.url;
        if (!baseUrl) {
          throw new Error('No base URL available for token exchange');
        }
        
        const response = await fetch(`${baseUrl}/oauth/token`, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            client_id: client.client_id,
            client_secret: client.client_secret || '',
            code: authorizationCode,
            redirect_uri: redirectUri || '',
            grant_type: 'authorization_code'
          })
        });
        
        if (!response.ok) {
          throw new Error(`Failed to exchange code: ${response.statusText}`);
        }
        
        const tokens = await response.json();
        
        return {
          access_token: tokens.access_token,
          token_type: tokens.token_type || 'bearer',
          scope: tokens.scope,
          refresh_token: tokens.refresh_token,
          expires_in: tokens.expires_in
        };
      },
      
      async exchangeRefreshToken(
        client: OAuthClientInformationFull, 
        refreshToken: string, 
        scopes?: string[], 
        resource?: URL
      ): Promise<OAuthTokens> {
        const baseUrl = config.http?.url || config.sse?.url;
        if (!baseUrl) {
          throw new Error('No base URL available for token refresh');
        }
        
        const response = await fetch(`${baseUrl}/oauth/token`, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            client_id: client.client_id,
            client_secret: client.client_secret || '',
            refresh_token: refreshToken,
            grant_type: 'refresh_token',
            scope: scopes?.join(' ') || ''
          })
        });
        
        if (!response.ok) {
          throw new Error(`Failed to refresh token: ${response.statusText}`);
        }
        
        const tokens = await response.json();
        
        return {
          access_token: tokens.access_token,
          token_type: tokens.token_type || 'bearer',
          scope: tokens.scope,
          refresh_token: tokens.refresh_token || refreshToken,
          expires_in: tokens.expires_in
        };
      },
      
      async verifyAccessToken(token: string): Promise<AuthInfo> {
        // For generic servers, we assume the token is valid
        return {
          token,
          clientId: `mcp-${serverId}`, // Use a constructed client ID
          scopes: ['read', 'write'],
          extra: {
            serverId,
            provider: 'generic'
          }
        };
      },
      
      async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        const baseUrl = config.http?.url || config.sse?.url;
        if (!baseUrl) {
          return; // Nothing to revoke if no endpoint
        }
        
        const response = await fetch(`${baseUrl}/oauth/revoke`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            token: request.token,
            token_type_hint: request.token_type_hint || 'access_token'
          })
        });
        
        if (!response.ok && response.status !== 404) {
          throw new Error(`Failed to revoke token: ${response.statusText}`);
        }
      }
    };
  }

  private isGitHubMcpServer(config: BackendServerConfig): boolean {
    const baseUrl = config.http?.url || config.sse?.url || '';
    return baseUrl.includes('githubcopilot.com') || 
           baseUrl.includes('github.com') ||
           config.id === 'github' ||
           config.name?.toLowerCase().includes('github');
  }

  // Implementation for the main OAuthServerProvider interface
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    // This should be called with server-specific context
    throw new Error('Use server-specific OAuth provider through getOAuthServerInfo()');
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    throw new Error('Use server-specific OAuth provider through getOAuthServerInfo()');
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull, 
    authorizationCode: string, 
    codeVerifier?: string, 
    redirectUri?: string, 
    resource?: URL
  ): Promise<OAuthTokens> {
    throw new Error('Use server-specific OAuth provider through getOAuthServerInfo()');
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull, 
    refreshToken: string, 
    scopes?: string[], 
    resource?: URL
  ): Promise<OAuthTokens> {
    throw new Error('Use server-specific OAuth provider through getOAuthServerInfo()');
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    throw new Error('Use server-specific OAuth provider through getOAuthServerInfo()');
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    throw new Error('Use server-specific OAuth provider through getOAuthServerInfo()');
  }

  // Diagnostic methods for dev tools
  getAllOAuthServers(): McpOAuthServerInfo[] {
    return Array.from(this.oauthServers.values());
  }

  getOAuthDiagnostics(): any {
    return {
      totalServers: this.oauthServers.size,
      servers: Array.from(this.oauthServers.values()).map(server => ({
        serverId: server.serverId,
        name: server.config.name,
        configured: true,
        needsOAuth: server.needsOAuth || false,
        oauthDetected: server.oauthDetected || false,
        authorizationUrl: server.authorizationUrl
      }))
    };
  }
}