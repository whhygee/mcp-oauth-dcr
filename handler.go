package mcpoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/oauth2"
)

// Endpoint paths. Mount handlers at these paths for metadata discovery to work.
const (
	PathRegister            = "/oauth/register"
	PathLogin               = "/oauth/login"
	PathCallback            = "/oauth/callback"
	PathToken               = "/oauth/token"
	PathProtectedResource   = "/.well-known/oauth-protected-resource"
	PathAuthorizationServer = "/.well-known/oauth-authorization-server"
)

// Handler implements OAuth 2.0 with Dynamic Client Registration (DCR) for MCP.
//
// It acts as a proxy between MCP clients and an OAuth provider that doesn't support DCR.
// During registration, it issues a random proxy token as the client_secret instead of
// exposing the real OAuth application secret. During token exchange, it validates the
// proxy token before forwarding the request to the upstream provider.
type Handler struct {
	baseURL     string
	mcpEndpoint string
	config      *oauth2.Config
	tokenStore  TokenStore
}

// NewHandler creates a new OAuth proxy handler.
func NewHandler(c *Config) *Handler {
	return &Handler{
		config: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURL,
			Scopes:       c.Scopes,
			Endpoint:     c.Endpoint,
		},
		tokenStore:  c.TokenStore,
		baseURL:     c.BaseURL,
		mcpEndpoint: c.MCPEndpoint,
	}
}

// HandleProtectedResourceMetadata serves the OAuth Protected Resource metadata document.
func (h *Handler) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"resource":              h.baseURL + h.mcpEndpoint,
		"authorization_servers": []string{h.baseURL},
	})
}

// HandleAuthorizationServerMetadata serves the OAuth Authorization Server metadata document.
func (h *Handler) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                           h.baseURL,
		"authorization_endpoint":           h.baseURL + PathLogin,
		"token_endpoint":                   h.baseURL + PathToken,
		"registration_endpoint":            h.baseURL + PathRegister,
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code"},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

// HandleRegister implements OAuth 2.0 Dynamic Client Registration.
// Returns a proxy token as client_secret instead of the real OAuth client secret.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid request body",
		})
		return
	}

	for _, uri := range req.RedirectURIs {
		if !IsAllowedRedirectURI(uri) {
			slog.Warn("mcpoauth: rejected registration with disallowed redirect_uri",
				slog.String("redirect_uri", uri),
				slog.String("remote_addr", r.RemoteAddr),
			)
			respond(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_redirect_uri",
				"error_description": "redirect_uri not allowed",
			})
			return
		}
	}

	t, err := GenToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.tokenStore.Put(r.Context(), t); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("mcpoauth: client registered",
		slog.Any("redirect_uris", req.RedirectURIs),
		slog.String("remote_addr", r.RemoteAddr),
	)

	respond(w, http.StatusCreated, map[string]interface{}{
		"client_id":     h.config.ClientID,
		"client_secret": t,
		"redirect_uris": req.RedirectURIs,
		"grant_types":   []string{"authorization_code"},
	})
}

// HandleLogin redirects the user to the OAuth provider's authorization page.
// Supports PKCE via code_challenge and code_challenge_method query parameters.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		state = randState()
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if !IsAllowedRedirectURI(redirectURI) {
		slog.Warn("mcpoauth: rejected login with disallowed redirect_uri",
			slog.String("redirect_uri", redirectURI),
			slog.String("remote_addr", r.RemoteAddr),
		)
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	if redirectURI != "" {
		state = state + "|" + redirectURI
	}

	opts := []oauth2.AuthCodeOption{}
	if codeChallenge := r.URL.Query().Get("code_challenge"); codeChallenge != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", codeChallenge))
		if method := r.URL.Query().Get("code_challenge_method"); method != "" {
			opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", method))
		}
	}

	http.Redirect(w, r, h.config.AuthCodeURL(state, opts...), http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth provider's redirect after user authorization.
// Parses state to recover the client's original state and redirect URI, then
// redirects back to the MCP client with the authorization code.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	var clientState, clientRedirectURI string
	if idx := strings.LastIndex(state, "|"); idx > 0 {
		clientState = state[:idx]
		clientRedirectURI = state[idx+1:]
	} else {
		clientState = state
	}

	redirectURL := clientRedirectURI
	if redirectURL == "" {
		redirectURL = DefaultRedirectURL
	}

	if !IsAllowedRedirectURI(redirectURL) {
		slog.Warn("mcpoauth: rejected callback with disallowed redirect_uri",
			slog.String("redirect_uri", redirectURL),
			slog.String("remote_addr", r.RemoteAddr),
		)
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		slog.Error("mcpoauth: failed to parse redirect URL", slog.Any("error", err), slog.String("redirectURL", redirectURL))
		http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
		return
	}

	q := parsedURL.Query()
	q.Set("code", code)
	q.Set("state", clientState)
	parsedURL.RawQuery = q.Encode()

	// JSON-encode the URL to escape quotes, backslashes, and </script> sequences.
	jsonURL, _ := json.Marshal(parsedURL.String())
	safeURL := string(jsonURL[1 : len(jsonURL)-1])

	w.Header().Set("Content-Type", "text/html")
	w.Write(fmt.Appendf(nil, successPage, safeURL))
}

// HandleToken exchanges an authorization code for an access token.
// Validates the proxy token before using the real client secret with the upstream provider.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientSecret := r.FormValue("client_secret")
	if clientSecret == "" || !h.tokenStore.Exists(r.Context(), clientSecret) {
		slog.Warn("mcpoauth: token exchange failed - invalid proxy token")
		respond(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "invalid or missing client_secret",
		})
		return
	}

	opts := []oauth2.AuthCodeOption{}
	if codeVerifier := r.FormValue("code_verifier"); codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	token, err := h.config.Exchange(context.Background(), r.FormValue("code"), opts...)
	if err != nil {
		slog.Error("mcpoauth: token exchange failed", slog.Any("error", err))
		respond(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	respond(w, http.StatusOK, map[string]string{
		"access_token": token.AccessToken,
		"token_type":   "bearer",
		"scope":        strings.Join(h.config.Scopes, " "),
	})
}

// WWWAuthenticateHeader returns the value for a WWW-Authenticate response header.
func (h *Handler) WWWAuthenticateHeader() string {
	return fmt.Sprintf(`Bearer realm="%s", resource_metadata="%s%s"`, h.baseURL, h.baseURL, PathProtectedResource)
}

// IsAllowedRedirectURI validates that a redirect URI is safe for MCP OAuth.
// Allows empty URIs, custom schemes in AllowedRedirectSchemes, and localhost/loopback addresses.
func IsAllowedRedirectURI(redirectURI string) bool {
	if redirectURI == "" {
		return true
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	if isLocalhostURI(parsed) {
		return true
	}

	return slices.Contains(AllowedRedirectSchemes, parsed.Scheme)
}

func isLocalhostURI(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func randState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func respond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

var successPage = `<!doctype html>
<meta charset="utf-8">
<title>Authenticated</title>
<style>
body { color:#1B1F23; background:#F6F8FA; font-size:14px; font-family:-apple-system,"Segoe UI",Helvetica,Arial,sans-serif; line-height:1.5; max-width:620px; margin:28px auto; text-align:center; }
h1 { font-size:24px; margin-bottom:0; }
p { margin-top:0; }
.box { border:1px solid #E1E4E8; background:white; padding:24px; margin:28px; }
</style>
<body>
<div class="box">
  <h1>Successfully authenticated</h1>
  <p>You can close this window.</p>
</div>
<script>window.location.href='%s';</script>
</body>`
