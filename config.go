package mcpoauth

import "golang.org/x/oauth2"

// Config configures the OAuth proxy handler.
type Config struct {
	// BaseURL is the public URL of your server (e.g., "https://example.com").
	BaseURL string
	// MCPEndpoint is the path where the MCP server is mounted (e.g., "/mcp").
	MCPEndpoint string
	// ClientID is the OAuth application client ID.
	ClientID string
	// ClientSecret is the real OAuth application client secret (kept server-side, never exposed).
	ClientSecret string
	// RedirectURL is the server's OAuth callback URL (e.g., "https://example.com/oauth/callback").
	RedirectURL string
	// Endpoint is the OAuth provider's authorization and token URLs.
	Endpoint oauth2.Endpoint
	// Scopes to request during authorization.
	Scopes []string
	// TokenStore persists proxy tokens for DCR validation.
	TokenStore TokenStore
	// PathPrefix is prepended to the register, login, callback and token paths
	// (e.g., "/mcp" mounts them at "/mcp/oauth/register" etc.). The .well-known
	// metadata paths are never prefixed, as required by RFC 8414 and RFC 9728.
	// Optional; defaults to "".
	PathPrefix string
	// SuccessPage is the HTML served after a successful callback. It must contain
	// exactly one %s verb, which receives the JavaScript-escaped client redirect URL.
	// Optional; defaults to DefaultSuccessPage.
	SuccessPage string
}

var (
	// AllowedRedirectSchemes defines URL schemes allowed for MCP client callbacks.
	// Custom schemes stay on the user's machine, making them safe for OAuth redirects.
	AllowedRedirectSchemes = []string{
		"cursor",
		"vscode",
		"vscode-insiders",
	}

	// DefaultRedirectURL is the fallback when no redirect_uri is provided in the callback.
	DefaultRedirectURL = "cursor://oauth/callback"
)
