/**
 * OAuth Consolidation Manager - Unified OAuth handling for MCP proxy server
 * 
 * This manager consolidates OAuth requirements from multiple backend MCP servers
 * into a single OAuth flow, allowing the MCP client to authenticate once while
 * the proxy handles authentication with all backend servers that require OAuth.
 * 
 * Based on MCP specification: https://modelcontextprotocol.io/specification/draft/basic/authorization
 */

import { Response, Request } from "express";
import { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { 
  OAuthClientInformationFull, 
  OAuthTokenRevocationRequest, 
  OAuthTokens,
  OAuthMetadata 
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { BackendServerConfig } from "../types.js";
import { Logger } from '../utils/logging.js';

function getComponentName() {
  return "OAuthConsolidationManager";
}



export interface ConsolidatedOAuthRequirement {
  serverId: string;
  config: BackendServerConfig;
  scopes: string[];
  authorizationUrl: string;
  tokenUrl: string;
  revocationUrl?: string;
  metadataUrl?: string;
  clientId?: string;
  clientSecret?: string;
  needsOAuth: boolean;
  lastError?: string;
}

export interface ConsolidatedToken {
  serverId: string;
  token: string;
  refreshToken?: string;
  expiresAt?: number;
  scopes: string[];
}

/**
 * In-memory client store for OAuth consolidation
 */
class ConsolidatedClientsStore implements OAuthRegisteredClientsStore {
  private clients: Map<string, OAuthClientInformationFull> = new Map();

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async registerClient(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): Promise<OAuthClientInformationFull> {
    const fullClient: OAuthClientInformationFull = {
      ...client,
      client_id: `mcp_consolidated_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      client_id_issued_at: Math.floor(Date.now() / 1000)
    };
    this.clients.set(fullClient.client_id, fullClient);
    return fullClient;
  }

  async storeClient(client: OAuthClientInformationFull): Promise<void> {
    this.clients.set(client.client_id, client);
  }

  getAllClients(): OAuthClientInformationFull[] {
    return Array.from(this.clients.values());
  }
}

/**
 * OAuth Consolidation Manager
 * 
 * Consolidates OAuth requirements from multiple backend servers into a single OAuth flow.
 * The client authenticates once with the proxy, and the proxy distributes tokens to backend servers.
 */
export class OAuthConsolidationManager implements OAuthServerProvider {
  private oauthRequirements: Map<string, ConsolidatedOAuthRequirement> = new Map();
  private activeTokens: Map<string, ConsolidatedToken[]> = new Map(); // clientId -> tokens
  private _clientsStore: ConsolidatedClientsStore;
  private baseUrl: string;
  private activeChallenges: Map<string, string> = new Map(); // authCode -> codeChallenge

  constructor(baseUrl: string = 'http://localhost:3001') {
    this.baseUrl = baseUrl;
    this._clientsStore = new ConsolidatedClientsStore();
    this.initializeDefaultClient();
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  /**
   * Initialize default client for the MCP proxy
   */
  private async initializeDefaultClient(): Promise<void> {
    const defaultClient: OAuthClientInformationFull = {
      client_id: 'mcp-proxy-consolidated',
      client_name: 'MCP Proxy Server (Consolidated OAuth)',
      redirect_uris: [
        `${this.baseUrl}/oauth/callback`,
        `${this.baseUrl}/.well-known/oauth-authorization-server/callback`
      ],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'mcp:read mcp:write mcp:admin',
      client_secret: `mcp_secret_${Date.now()}_${Math.random().toString(36)}`
    };

    await this._clientsStore.storeClient(defaultClient);
    Logger.info(`Initialized consolidated OAuth client: ${defaultClient.client_id}`, { component: getComponentName() });
  }

  /**
   * Register an OAuth requirement from a backend server
   */
  async registerOAuthRequirement(serverId: string, config: BackendServerConfig, error?: string): Promise<boolean> {
    Logger.debug(`Registering OAuth requirement for server: ${serverId} (${config.name})`, { component: getComponentName() });

    const scopes = this.determineRequiredScopes(config, error);
    const urls = this.buildOAuthUrls(config);

    const requirement: ConsolidatedOAuthRequirement = {
      serverId,
      config,
      scopes,
      authorizationUrl: urls.authorizationUrl,
      tokenUrl: urls.tokenUrl,
      revocationUrl: urls.revocationUrl,
      metadataUrl: urls.metadataUrl,
      clientId: this.extractClientId(config),
      clientSecret: this.extractClientSecret(config),
      needsOAuth: true,
      lastError: error
    };

    this.oauthRequirements.set(serverId, requirement);
    Logger.debug(`OAuth requirement registered for ${serverId}: scopes=${scopes.join(', ')}`, { component: getComponentName() });
    return true;
  }

  /**
   * Detect OAuth requirements from error messages
   */
  async detectOAuthFromError(serverId: string, config: BackendServerConfig, error: string): Promise<boolean> {
    const oauthIndicators = [
      'authorization', 'unauthorized', '401', 'access_token', 'oauth',
      'bearer', 'authentication required', 'missing required authorization header',
      'invalid_token', 'token_expired', 'authentication_failed'
    ];

    const errorLower = error.toLowerCase();
    const needsOAuth = oauthIndicators.some(indicator => errorLower.includes(indicator));

    if (needsOAuth) {
      return await this.registerOAuthRequirement(serverId, config, error);
    }

    return false;
  }

  /**
   * Force OAuth detection for known OAuth-enabled servers
   */
  async forceOAuthDetection(serverConfigs: BackendServerConfig[]): Promise<void> {
    Logger.debug("Force detecting OAuth requirements for all servers...", { component: getComponentName() });

    for (const config of serverConfigs) {
      if (!config.enabled) {continue};

      // Force OAuth for known OAuth-enabled servers
      if (this.isKnownOAuthServer(config)) {
        Logger.debug(`Force enabling OAuth for known server: ${config.id}`, { component: getComponentName() });
        await this.registerOAuthRequirement(
          config.id, 
          config, 
          "Force OAuth detection for known OAuth-enabled server"
        );
      }
    }
  }

  /**
   * Check if server is a known OAuth-enabled server
   */
  private isKnownOAuthServer(config: BackendServerConfig): boolean {
    const baseUrl = config.http?.url || config.sse?.url || '';
    const serverId = config.id?.toLowerCase() || '';
    const serverName = config.name?.toLowerCase() || '';

    // Known OAuth-enabled servers
    const oauthServers = [
      'github', 'google', 'microsoft', 'slack', 'discord', 'twitter',
      'facebook', 'linkedin', 'dropbox', 'spotify', 'gitlab'
    ];

    return (
      baseUrl.includes('githubcopilot.com') ||
      baseUrl.includes('github.com') ||
      baseUrl.includes('googleapis.com') ||
      baseUrl.includes('microsoftgraph.com') ||
      oauthServers.some(oauth => 
        serverId.includes(oauth) || 
        serverName.includes(oauth) || 
        baseUrl.includes(oauth)
      )
    );
  }

  /**
   * Get consolidated OAuth metadata for the proxy server
   */
  getConsolidatedMetadata(): OAuthMetadata {
    const allScopes = this.getAllConsolidatedScopes();
    
    return {
      issuer: `${this.baseUrl}/oauth`,
      authorization_endpoint: `${this.baseUrl}/oauth/authorize`,
      token_endpoint: `${this.baseUrl}/oauth/token`,
      revocation_endpoint: `${this.baseUrl}/oauth/revoke`,
      jwks_uri: `${this.baseUrl}/oauth/jwks`,
      scopes_supported: allScopes,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256', 'plain'],
      service_documentation: `${this.baseUrl}/oauth/docs`,
      ui_locales_supported: ['en'],
      registration_endpoint: `${this.baseUrl}/oauth/register`
    };
  }

  /**
   * Get all consolidated scopes from all backend servers
   */
  private getAllConsolidatedScopes(): string[] {
    const allScopes = new Set<string>();
    
    // Add standard MCP scopes
    allScopes.add('mcp:read');
    allScopes.add('mcp:write');
    allScopes.add('mcp:admin');
    
    // Add scopes from all OAuth requirements
    for (const requirement of this.oauthRequirements.values()) {
      requirement.scopes.forEach(scope => allScopes.add(scope));
    }
    
    return Array.from(allScopes).sort();
  }

  /**
   * Build OAuth URLs for a backend server
   */
  private buildOAuthUrls(config: BackendServerConfig): {
    authorizationUrl: string;
    tokenUrl: string;
    revocationUrl?: string;
    metadataUrl?: string;
  } {
    const baseUrl = config.http?.url || config.sse?.url || '';

    // Special handling for GitHub MCP Server
    if (this.isGitHubMcpServer(config)) {
      return {
        authorizationUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        revocationUrl: 'https://github.com/login/oauth/revoke',
        metadataUrl: 'https://github.com/.well-known/oauth-authorization-server'
      };
    }

    // Generic OAuth URLs
    try {
      const url = new URL(baseUrl);
      return {
        authorizationUrl: `${url.origin}/oauth/authorize`,
        tokenUrl: `${url.origin}/oauth/token`,
        revocationUrl: `${url.origin}/oauth/revoke`,
        metadataUrl: `${url.origin}/.well-known/oauth-authorization-server`
      };
    } catch {
      return {
        authorizationUrl: `${baseUrl}/oauth/authorize`,
        tokenUrl: `${baseUrl}/oauth/token`,
        revocationUrl: `${baseUrl}/oauth/revoke`,
        metadataUrl: `${baseUrl}/.well-known/oauth-authorization-server`
      };
    }
  }

  /**
   * Determine required scopes for a server
   */
  private determineRequiredScopes(config: BackendServerConfig, error?: string): string[] {
    const scopes = new Set<string>();

    // Base MCP scopes
    scopes.add('mcp:read');
    scopes.add('mcp:write');

    // GitHub-specific scopes
    if (this.isGitHubMcpServer(config)) {
      scopes.add('repo');
      scopes.add('read:user');
      scopes.add('read:org');
    }

    // Extract scopes from error message if available
    if (error) {
      const scopePattern = /scope[s]?[:=]\s*([^,\s]+)/gi;
      let match;
      while ((match = scopePattern.exec(error)) !== null) {
        scopes.add(match[1]);
      }
    }

    return Array.from(scopes);
  }

  /**
   * Extract client ID from config or environment
   */
  private extractClientId(config: BackendServerConfig): string | undefined {
    if (this.isGitHubMcpServer(config)) {
      return process.env.GITHUB_CLIENT_ID;
    }
    // For now, return undefined as BackendServerConfig doesn't have oauth property
    // This could be extended when oauth config is added to the type
    return undefined;
  }

  /**
   * Extract client secret from config or environment
   */
  private extractClientSecret(config: BackendServerConfig): string | undefined {
    if (this.isGitHubMcpServer(config)) {
      return process.env.GITHUB_CLIENT_SECRET;
    }
    // For now, return undefined as BackendServerConfig doesn't have oauth property
    // This could be extended when oauth config is added to the type
    return undefined;
  }

  /**
   * Check if this is the GitHub MCP server
   */
  private isGitHubMcpServer(config: BackendServerConfig): boolean {
    const baseUrl = config.http?.url || config.sse?.url || '';
    return baseUrl.includes('githubcopilot.com') || 
           baseUrl.includes('github.com') ||
           config.id === 'github' ||
           config.name?.toLowerCase().includes('github');
  }

  // Implementation of OAuthServerProvider interface

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    Logger.info(`Starting consolidated OAuth authorization for client: ${client.client_id}`, { component: getComponentName() });
    
    // Store the code challenge for later verification
    if (params.codeChallenge) {
      this.activeChallenges.set(params.state || 'default', params.codeChallenge);
    }

    // Build consolidated authorization URL
    const authUrl = new URL(`${this.baseUrl}/oauth/authorize`);
    authUrl.searchParams.set('client_id', client.client_id);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', params.redirectUri);
    authUrl.searchParams.set('scope', this.getAllConsolidatedScopes().join(' '));
    authUrl.searchParams.set('state', params.state || '');

    if (params.codeChallenge) {
      authUrl.searchParams.set('code_challenge', params.codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256'); // Default to S256
    }

    Logger.debug(`Redirecting to consolidated OAuth: ${authUrl.toString()}`, { component: getComponentName() });
    res.redirect(authUrl.toString());
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    // Find the stored challenge for this authorization attempt
    for (const [state, challenge] of this.activeChallenges.entries()) {
      if (state === 'default' || authorizationCode.includes(state)) {
        return challenge;
      }
    }
    return '';
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    Logger.debug(`Exchanging consolidated authorization code for tokens`, { component: getComponentName() });

    // In a real implementation, this would exchange the consolidated auth code
    // for tokens from all backend servers. For now, we'll create a master token.
    const masterToken = `mcp_consolidated_${Date.now()}_${Math.random().toString(36)}`;
    const refreshToken = `mcp_refresh_${Date.now()}_${Math.random().toString(36)}`;

    // Exchange tokens with all backend servers that need OAuth
    const serverTokens: ConsolidatedToken[] = [];
    
    for (const requirement of this.oauthRequirements.values()) {
      try {
        const backendTokens = await this.exchangeWithBackendServer(
          requirement,
          authorizationCode,
          codeVerifier,
          redirectUri
        );
        serverTokens.push(backendTokens);
      } catch (error) {
        Logger.logError(error as Error, `Failed to exchange tokens with ${requirement.serverId}`, { component: getComponentName() });
        // Continue with other servers even if one fails
      }
    }

    // Store consolidated tokens
    this.activeTokens.set(client.client_id, serverTokens);

    return {
      access_token: masterToken,
      token_type: 'bearer',
      scope: this.getAllConsolidatedScopes().join(' '),
      refresh_token: refreshToken,
      expires_in: 3600
    };
  }

  /**
   * Exchange authorization code with a specific backend server
   */
  private async exchangeWithBackendServer(
    requirement: ConsolidatedOAuthRequirement,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string
  ): Promise<ConsolidatedToken> {
    Logger.debug(`Exchanging tokens with backend server: ${requirement.serverId}`, { component: getComponentName() });

    if (this.isGitHubMcpServer(requirement.config)) {
      return await this.exchangeGitHubTokens(requirement, authorizationCode, redirectUri);
    } else {
      return await this.exchangeGenericTokens(requirement, authorizationCode, codeVerifier, redirectUri);
    }
  }

  /**
   * Exchange tokens with GitHub OAuth
   */
  private async exchangeGitHubTokens(
    requirement: ConsolidatedOAuthRequirement,
    authorizationCode: string,
    redirectUri?: string
  ): Promise<ConsolidatedToken> {
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: requirement.clientId || process.env.GITHUB_CLIENT_ID || '',
        client_secret: requirement.clientSecret || process.env.GITHUB_CLIENT_SECRET || '',
        code: authorizationCode,
        redirect_uri: redirectUri || ''
      })
    });

    if (!response.ok) {
      throw new Error(`GitHub token exchange failed: ${response.statusText}`);
    }

    const tokens = await response.json();

    return {
      serverId: requirement.serverId,
      token: tokens.access_token,
      refreshToken: tokens.refresh_token,
      scopes: requirement.scopes,
      expiresAt: tokens.expires_in ? Date.now() + (tokens.expires_in * 1000) : undefined
    };
  }

  /**
   * Exchange tokens with generic OAuth server
   */
  private async exchangeGenericTokens(
    requirement: ConsolidatedOAuthRequirement,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string
  ): Promise<ConsolidatedToken> {
    const response = await fetch(requirement.tokenUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: requirement.clientId || 'mcp-proxy',
        client_secret: requirement.clientSecret || '',
        code: authorizationCode,
        redirect_uri: redirectUri || '',
        grant_type: 'authorization_code',
        ...(codeVerifier && { code_verifier: codeVerifier })
      })
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed for ${requirement.serverId}: ${response.statusText}`);
    }

    const tokens = await response.json();

    return {
      serverId: requirement.serverId,
      token: tokens.access_token,
      refreshToken: tokens.refresh_token,
      scopes: requirement.scopes,
      expiresAt: tokens.expires_in ? Date.now() + (tokens.expires_in * 1000) : undefined
    };
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    Logger.debug(`Refreshing consolidated tokens for client: ${client.client_id}`, { component: getComponentName() });

    // Refresh tokens with all backend servers
    const serverTokens = this.activeTokens.get(client.client_id) || [];
    const refreshedTokens: ConsolidatedToken[] = [];

    for (const serverToken of serverTokens) {
      if (serverToken.refreshToken) {
        try {
          const requirement = this.oauthRequirements.get(serverToken.serverId);
          if (requirement) {
            const refreshed = await this.refreshBackendToken(requirement, serverToken);
            refreshedTokens.push(refreshed);
          }
        } catch (error) {
          Logger.logError(error as Error, `Failed to refresh token for ${serverToken.serverId}`, { component: getComponentName() });
          // Keep the original token if refresh fails
          refreshedTokens.push(serverToken);
        }
      } else {
        refreshedTokens.push(serverToken);
      }
    }

    // Update stored tokens
    this.activeTokens.set(client.client_id, refreshedTokens);

    // Return new master token
    const newMasterToken = `mcp_consolidated_${Date.now()}_${Math.random().toString(36)}`;
    
    return {
      access_token: newMasterToken,
      token_type: 'bearer',
      scope: scopes?.join(' ') || this.getAllConsolidatedScopes().join(' '),
      refresh_token: refreshToken,
      expires_in: 3600
    };
  }

  /**
   * Refresh token with a specific backend server
   */
  private async refreshBackendToken(
    requirement: ConsolidatedOAuthRequirement,
    serverToken: ConsolidatedToken
  ): Promise<ConsolidatedToken> {
    if (this.isGitHubMcpServer(requirement.config)) {
      // GitHub doesn't support refresh tokens in the same way
      throw new Error('GitHub OAuth refresh tokens not supported');
    }

    const response = await fetch(requirement.tokenUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: requirement.clientId || 'mcp-proxy',
        client_secret: requirement.clientSecret || '',
        refresh_token: serverToken.refreshToken || '',
        grant_type: 'refresh_token',
        scope: serverToken.scopes.join(' ')
      })
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed for ${requirement.serverId}: ${response.statusText}`);
    }

    const tokens = await response.json();

    return {
      serverId: serverToken.serverId,
      token: tokens.access_token,
      refreshToken: tokens.refresh_token || serverToken.refreshToken,
      scopes: serverToken.scopes,
      expiresAt: tokens.expires_in ? Date.now() + (tokens.expires_in * 1000) : undefined
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    Logger.debug(`Verifying consolidated access token`, { component: getComponentName() });

    // Find the client that has this token
    for (const [clientId, serverTokens] of this.activeTokens.entries()) {
      // In a real implementation, you'd verify the master token format
      if (token.startsWith('mcp_consolidated_')) {
        return {
          token,
          clientId,
          scopes: this.getAllConsolidatedScopes(),
          extra: {
            provider: 'mcp-proxy-consolidated',
            serverTokens: serverTokens.map(st => ({
              serverId: st.serverId,
              scopes: st.scopes
            }))
          }
        };
      }
    }

    throw new Error('Invalid or expired consolidated token');
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    Logger.debug(`Revoking consolidated tokens for client: ${client.client_id}`, { component: getComponentName() });

    // Revoke tokens with all backend servers
    const serverTokens = this.activeTokens.get(client.client_id) || [];

    for (const serverToken of serverTokens) {
      try {
        const requirement = this.oauthRequirements.get(serverToken.serverId);
        if (requirement && requirement.revocationUrl) {
          await this.revokeBackendToken(requirement, serverToken);
        }
      } catch (error) {
        Logger.logError(error as Error, `Failed to revoke token for ${serverToken.serverId}`, { component: getComponentName() });
        // Continue revoking other tokens even if one fails
      }
    }

    // Remove stored tokens
    this.activeTokens.delete(client.client_id);
  }

  /**
   * Revoke token with a specific backend server
   */
  private async revokeBackendToken(
    requirement: ConsolidatedOAuthRequirement,
    serverToken: ConsolidatedToken
  ): Promise<void> {
    if (!requirement.revocationUrl) {return};

    const response = await fetch(requirement.revocationUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        token: serverToken.token,
        token_type_hint: 'access_token'
      })
    });

    if (!response.ok && response.status !== 404) {
      throw new Error(`Token revocation failed for ${requirement.serverId}: ${response.statusText}`);
    }
  }

  /**
   * Get token for a specific backend server
   */
  getServerToken(clientId: string, serverId: string): string | undefined {
    const serverTokens = this.activeTokens.get(clientId) || [];
    const serverToken = serverTokens.find(token => token.serverId === serverId);
    return serverToken?.token;
  }

  /**
   * Get all active OAuth requirements
   */
  getOAuthRequirements(): ConsolidatedOAuthRequirement[] {
    return Array.from(this.oauthRequirements.values());
  }

  /**
   * Get diagnostic information
   */
  getDiagnostics() {
    const requirements = Array.from(this.oauthRequirements.values());
    const clients = this._clientsStore.getAllClients();
    
    return {
      totalRequirements: requirements.length,
      activeClients: this.activeTokens.size,
      registeredClients: clients.length,
      consolidatedScopes: this.getAllConsolidatedScopes(),
      requirements: requirements.map(req => ({
        serverId: req.serverId,
        serverName: req.config.name,
        scopes: req.scopes,
        needsOAuth: req.needsOAuth,
        authorizationUrl: req.authorizationUrl,
        tokenUrl: req.tokenUrl,
        lastError: req.lastError
      })),
      activeTokens: Array.from(this.activeTokens.entries()).map(([clientId, tokens]) => ({
        clientId,
        serverCount: tokens.length,
        servers: tokens.map(token => ({
          serverId: token.serverId,
          scopes: token.scopes,
          hasRefreshToken: !!token.refreshToken,
          expiresAt: token.expiresAt
        }))
      }))
    };
  }

  /**
   * Check if any server needs OAuth
   */
  hasOAuthRequirements(): boolean {
    return this.oauthRequirements.size > 0;
  }

  /**
   * Remove OAuth requirement for a server
   */
  removeOAuthRequirement(serverId: string): void {
    this.oauthRequirements.delete(serverId);
    
    // Remove tokens for this server from all clients
    for (const [clientId, serverTokens] of this.activeTokens.entries()) {
      const filteredTokens = serverTokens.filter(token => token.serverId !== serverId);
      if (filteredTokens.length === 0) {
        this.activeTokens.delete(clientId);
      } else {
        this.activeTokens.set(clientId, filteredTokens);
      }
    }
  }

  /**
   * Get OAuth server information for a specific server ID
   */
  getOAuthServerInfo(serverId: string): { provider: OAuthServerProvider; clientStore: OAuthRegisteredClientsStore; serverId: string; config: BackendServerConfig } | null {
    const requirement = this.oauthRequirements.get(serverId);
    if (!requirement) {
      return null;
    }

    return {
      provider: this,
      clientStore: this._clientsStore,
      serverId: requirement.serverId,
      config: requirement.config
    };
  }

  /**
   * Get all OAuth servers that have been registered
   */
  getAllOAuthServers(): Array<{ serverId: string; config: BackendServerConfig; provider: OAuthServerProvider; clientStore: OAuthRegisteredClientsStore }> {
    return Array.from(this.oauthRequirements.values()).map(requirement => ({
      serverId: requirement.serverId,
      config: requirement.config,
      provider: this,
      clientStore: this._clientsStore
    }));
  }
}