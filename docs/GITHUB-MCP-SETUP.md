# GitHub MCP Server Setup

## Overview

The GitHub MCP Server provides comprehensive GitHub integration capabilities including repository management, issues, pull requests, code analysis, and workflow automation. This server connects to GitHub's API via HTTP transport and requires proper authentication.

## Authentication Setup

### 1. Create a GitHub Personal Access Token

1. **Navigate to GitHub Settings**:
   - Go to [GitHub.com](https://github.com) → Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Or visit directly: https://github.com/settings/personal-access-tokens/tokens

2. **Generate New Token**:
   - Click "Generate new token (classic)"
   - Give it a descriptive name like "MCP Everything Server"
   - Set expiration as needed (recommended: 90 days or no expiration for development)

3. **Select Required Scopes**:
   ```
   ✅ repo - Full control of private repositories
   ✅ read:user - Read user profile data
   ✅ user:email - Access user email addresses
   ✅ notifications - Access notifications
   ✅ workflow - Update GitHub Action workflows
   ```

4. **Copy the Token**: Save the generated token securely (you won't see it again)

### 2. Configure Environment Variables

1. **Copy Environment Template**:
   ```bash
   cp .env.example .env
   ```

2. **Set GitHub Token**:
   ```bash
   # Edit .env file and replace the placeholder
   GITHUB_TOKEN=ghp_your_actual_github_token_here
   ```

   **Example**:
   ```bash
   # GitHub MCP Server Configuration
   GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678
   ```

## Configuration

The GitHub MCP server is configured in `apps/mcp/mcp-proxy-config.json`:

```json
{
  "id": "github",
  "name": "GitHub MCP Server (Remote)",
  "description": "GitHub repository management, issues, PRs, code analysis, and workflow automation via remote server",
  "transportType": "http",
  "enabled": true,
  "http": {
    "url": "https://api.githubcopilot.com/mcp/",
    "headers": {
      "Authorization": "Bearer ${GITHUB_TOKEN}"
    },
    "timeout": 30000
  },
  "security": {
    "allowedTools": [
      "get_repo",
      "list_repos", 
      "get_file_contents",
      "search_repositories",
      "search_code",
      "list_issues",
      "get_issue",
      "create_issue",
      "update_issue",
      "list_pull_requests",
      "get_pull_request",
      "create_pull_request",
      "list_commits",
      "get_commit",
      "list_branches",
      "create_branch",
      "get_workflow_runs",
      "get_workflow_run",
      "list_notifications",
      "mark_notifications_read"
    ],
    "requireAuth": false
  }
}
```

## Available Tools

The GitHub MCP server provides the following capabilities:

### Repository Management
- `get_repo` - Get repository information
- `list_repos` - List repositories for a user/organization
- `get_file_contents` - Read file contents from repository
- `search_repositories` - Search for repositories
- `search_code` - Search code within repositories

### Issues Management
- `list_issues` - List repository issues
- `get_issue` - Get specific issue details
- `create_issue` - Create new issue
- `update_issue` - Update existing issue

### Pull Requests
- `list_pull_requests` - List repository pull requests
- `get_pull_request` - Get specific pull request details
- `create_pull_request` - Create new pull request

### Version Control
- `list_commits` - List repository commits
- `get_commit` - Get specific commit details
- `list_branches` - List repository branches
- `create_branch` - Create new branch

### Workflows & Notifications
- `get_workflow_runs` - Get workflow run information
- `get_workflow_run` - Get specific workflow run details
- `list_notifications` - List user notifications
- `mark_notifications_read` - Mark notifications as read

## Starting the Server

1. **Set Environment Variables**: Ensure `.env` file has your `GITHUB_TOKEN`

2. **Start via Docker**:
   ```bash
   docker-compose -f docker-compose.mcp.yml up
   ```

3. **Test Connection**: Use MCP Inspector at http://localhost:3001 to verify the GitHub server is connected

## Troubleshooting

### Common Issues

1. **HTTP 401 - Missing Authorization Header**:
   ```
   Error POSTing to endpoint (HTTP 401): bad request: missing required Authorization header
   ```
   **Solution**: Verify your `GITHUB_TOKEN` is set correctly in `.env`

2. **HTTP 403 - Token Invalid**:
   ```
   Error POSTing to endpoint (HTTP 403): forbidden
   ```
   **Solutions**:
   - Check token hasn't expired
   - Verify token has required scopes
   - Regenerate token if necessary

3. **HTTP 404 - Server Not Found**:
   ```
   Error connecting to GitHub MCP server
   ```
   **Solutions**:
   - Verify URL: `https://api.githubcopilot.com/mcp/`
   - Check internet connection
   - Ensure server endpoint is accessible

4. **Environment Variable Not Loading**:
   ```
   Authorization: Bearer ${GITHUB_TOKEN}
   ```
   **Solutions**:
   - Ensure `.env` file exists in project root
   - Restart Docker containers after changing `.env`
   - Check for typos in variable name

### Verification Steps

1. **Check Environment Variables**:
   ```bash
   # In container or terminal
   echo $GITHUB_TOKEN
   ```

2. **Test GitHub Token**:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" https://api.github.com/user
   ```

3. **Check MCP Inspector Logs**:
   ```bash
   docker-compose -f docker-compose.mcp.yml logs github
   ```

### Debug Mode

Enable verbose logging for GitHub MCP server:

```json
{
  "id": "github",
  "debug": true,
  "http": {
    "url": "https://api.githubcopilot.com/mcp/",
    "headers": {
      "Authorization": "Bearer ${GITHUB_TOKEN}",
      "X-Debug": "true"
    }
  }
}
```

## Security Considerations

1. **Token Storage**: Never commit `.env` files with real tokens to version control
2. **Token Scope**: Only grant minimum required permissions
3. **Token Rotation**: Regularly rotate personal access tokens
4. **Environment Isolation**: Use different tokens for development/production

## Usage Examples

Once configured, you can use the GitHub tools through the MCP interface:

```javascript
// Example: List repositories
await client.callTool('github__list_repos', {
  username: 'octocat',
  type: 'public'
});

// Example: Create an issue
await client.callTool('github__create_issue', {
  owner: 'octocat',
  repo: 'Hello-World',
  title: 'Bug report',
  body: 'Something is not working...'
});
```

## Related Documentation

- [MCP Inspector Setup](./MCP-INSPECTOR-SETUP.md) - For testing the GitHub server
- [Development Workflow](./DEVELOPMENT-WORKFLOW.md) - For development practices
- [Environment Template System](./ENVIRONMENT-TEMPLATE-SYSTEM.md) - For environment configuration
