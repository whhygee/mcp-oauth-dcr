package mcpoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type memStore struct{ m map[string]bool }

func (s *memStore) Put(_ context.Context, t string) error   { s.m[t] = true; return nil }
func (s *memStore) Exists(_ context.Context, t string) bool { return s.m[t] }

func newTestHandler(prefix, page string) (*Handler, *memStore) {
	st := &memStore{m: map[string]bool{}}
	h := NewHandler(&Config{
		BaseURL:     "https://example.com",
		MCPEndpoint: "/mcp",
		ClientID:    "cid",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://idp/auth", TokenURL: "https://idp/token"},
		TokenStore:  st,
		PathPrefix:  prefix,
		SuccessPage: page,
	})
	return h, st
}

func TestPathPrefixAndMetadata(t *testing.T) {
	h, _ := newTestHandler("/mcp/", "")
	if got := h.TokenPath(); got != "/mcp/oauth/token" {
		t.Fatalf("TokenPath = %q", got)
	}
	if got := h.config.RedirectURL; got != "https://example.com/mcp/oauth/callback" {
		t.Fatalf("default RedirectURL = %q", got)
	}

	mux := http.NewServeMux()
	h.Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathAuthorizationServer, nil))
	var md map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&md); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"authorization_endpoint": "https://example.com/mcp/oauth/login",
		"token_endpoint":         "https://example.com/mcp/oauth/token",
		"registration_endpoint":  "https://example.com/mcp/oauth/register",
	} {
		if md[k] != want {
			t.Errorf("%s = %v, want %s", k, md[k], want)
		}
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathProtectedResource, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("well-known must stay at root, got %d", rec.Code)
	}
}

func TestHandleTokenBasicAuth(t *testing.T) {
	h, st := newTestHandler("", "")
	st.m["secret"] = true

	// Basic header carries the proxy token; passes validation and reaches the
	// upstream exchange (which fails here because the IdP is fake) => not 401.
	req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(url.Values{"code": {"c"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cid", "secret")
	rec := httptest.NewRecorder()
	h.HandleToken(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("Basic client_secret rejected: %s", rec.Body)
	}

	req = httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(url.Values{"code": {"c"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cid", "wrong")
	rec = httptest.NewRecorder()
	h.HandleToken(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown proxy token accepted: %d", rec.Code)
	}
}

func TestCallbackCustomSuccessPage(t *testing.T) {
	h, _ := newTestHandler("", "<html>custom %s</html>")
	req := httptest.NewRequest(http.MethodGet, PathCallback+"?code=abc&state=s1|http://localhost:1234/cb", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)
	body := rec.Body.String()
	if !strings.HasPrefix(body, "<html>custom ") || !strings.Contains(body, "localhost:1234/cb?code=abc\\u0026state=s1") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestIsAllowedRedirectURI(t *testing.T) {
	for uri, want := range map[string]bool{
		"":                         true,
		"cursor://oauth/callback":  true,
		"vscode://x":               true,
		"http://localhost:3000/cb": true,
		"http://127.0.0.1/cb":      true,
		"https://evil.example/cb":  false,
		"http://evil.example/cb":   false,
	} {
		if got := IsAllowedRedirectURI(uri); got != want {
			t.Errorf("%q = %v, want %v", uri, got, want)
		}
	}
}
