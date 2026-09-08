# mcp-oauth-dcr

OAuth 2.0 proxy that adds [Dynamic Client Registration (DCR)](https://datatracker.ietf.org/doc/html/rfc7591) to OAuth providers that don't support it natively — like GitHub. Built for [MCP](https://modelcontextprotocol.io/) servers, which require DCR.

## The problem

The MCP spec requires OAuth servers to support Dynamic Client Registration. GitHub OAuth doesn't. If you're building an MCP server that authenticates via GitHub, you're stuck.

## How it works

This library sits between MCP clients and GitHub (or any OAuth provider), proxying the OAuth flow:

1. **Registration** — MCP client calls `/oauth/register`. Instead of forwarding to GitHub (which would fail), the library generates a random **proxy token** and returns it as the `client_secret`. The real GitHub client secret never leaves your server.
2. **Authorization** — `/oauth/login` redirects to GitHub's authorize page, forwarding PKCE parameters.
3. **Callback** — `/oauth/callback` receives GitHub's redirect and bounces the user back to the MCP client (Cursor, VS Code, Claude Code, etc.).
4. **Token exchange** — `/oauth/token` validates the proxy token, then exchanges the authorization code with GitHub using the real client secret. The proxy token is read from the `client_secret` form field (`client_secret_post`) or from the `Authorization: Basic` header (`client_secret_basic`, the RFC 6749 default used by Claude Code).

The library also serves the `.well-known` metadata documents that MCP clients use for discovery.

## Usage

```go
import (
    "github.com/whhygee/mcp-oauth-dcr"
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

h.Mount(mux)
```

`Mount` registers the six handlers. To wire them yourself, use the path methods (`h.RegisterPath()`, `h.LoginPath()`, `h.CallbackPath()`, `h.TokenPath()`) together with `mcpoauth.PathProtectedResource` and `mcpoauth.PathAuthorizationServer`.

If `RedirectURL` is empty it defaults to `BaseURL + h.CallbackPath()`.

### Custom paths

Set `PathPrefix` to mount the four OAuth endpoints under another prefix. `PathPrefix: "/mcp"` gives `/mcp/oauth/register`, `/mcp/oauth/login`, `/mcp/oauth/callback` and `/mcp/oauth/token`. The metadata documents advertise the prefixed paths. The two `.well-known` paths are never prefixed, as RFC 8414 and RFC 9728 require them at the origin root.

### Custom success page

Set `SuccessPage` to replace the HTML shown after the callback. It must contain exactly one `%s`, which receives the JavaScript-escaped redirect URL back to the MCP client. `mcpoauth.DefaultSuccessPage` is the default.

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
