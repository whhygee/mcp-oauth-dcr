# mcp-oauth-dcr

OAuth 2.0 proxy that adds [Dynamic Client Registration (DCR)](https://datatracker.ietf.org/doc/html/rfc7591) to OAuth providers that don't support it natively — like GitHub. Built for [MCP](https://modelcontextprotocol.io/) servers, which require DCR.

## The problem

The MCP spec requires OAuth servers to support Dynamic Client Registration. GitHub OAuth doesn't. If you're building an MCP server that authenticates via GitHub, you're stuck.

## How it works

This library sits between MCP clients and GitHub (or any OAuth provider), proxying the OAuth flow:

1. **Registration** — MCP client calls `/oauth/register`. Instead of forwarding to GitHub (which would fail), the library generates a random **proxy token** and returns it as the `client_secret`. The real GitHub client secret never leaves your server.
2. **Authorization** — `/oauth/login` redirects to GitHub's authorize page, forwarding PKCE parameters.
3. **Callback** — `/oauth/callback` receives GitHub's redirect and bounces the user back to the MCP client (Cursor, VS Code, Claude Code, etc.).
4. **Token exchange** — `/oauth/token` validates the proxy token, then exchanges the authorization code with GitHub using the real client secret.

The library also serves the `.well-known` metadata documents that MCP clients use for discovery.

## Usage

```go
import (
    "github.com/whygee/mcpoauth-github"
    "golang.org/x/oauth2/github"
)

h := mcpoauth.NewHandler(&mcpoauth.Config{
    BaseURL:      "https://example.com",
    MCPEndpoint:  "/mcp",
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    RedirectURL:  "https://example.com/oauth/callback",
    Endpoint:     github.Endpoint,
    Scopes:       []string{"user", "repo"},
    TokenStore:   myStore, // you provide this
})

mux.HandleFunc(mcpoauth.PathProtectedResource, h.HandleProtectedResourceMetadata)
mux.HandleFunc(mcpoauth.PathAuthorizationServer, h.HandleAuthorizationServerMetadata)
mux.HandleFunc(mcpoauth.PathRegister, h.HandleRegister)
mux.HandleFunc(mcpoauth.PathLogin, h.HandleLogin)
mux.HandleFunc(mcpoauth.PathCallback, h.HandleCallback)
mux.HandleFunc(mcpoauth.PathToken, h.HandleToken)
```

### TokenStore

You need to provide a `TokenStore` implementation to persist proxy tokens. The interface is two methods:

```go
type TokenStore interface {
    Put(ctx context.Context, token string) error
    Exists(ctx context.Context, token string) bool
}
```

Back it with whatever you have — Redis, SQL, Datastore, or an in-memory map for development.

### Redirect URI allowlist

Only known-safe redirect URIs are accepted: custom schemes (`cursor://`, `vscode://`, `vscode-insiders://`) and localhost addresses. Override `AllowedRedirectSchemes` to add more:

```go
mcpoauth.AllowedRedirectSchemes = append(mcpoauth.AllowedRedirectSchemes, "myapp")
```

### Not just GitHub

Despite the name, `Endpoint` accepts any `oauth2.Endpoint`. If your OAuth provider lacks DCR support, this works for it too.

## License

MIT
