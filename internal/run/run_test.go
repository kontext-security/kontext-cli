package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kontext-dev/kontext-cli/internal/auth"
	"github.com/kontext-dev/kontext-cli/internal/credential"
)

func TestFilterArgs(t *testing.T) {
	t.Parallel()

	args := []string{
		"--settings", "user-settings.json",
		"--dangerously-skip-permissions",
		"--setting-sources=local",
		"--allowed",
		"value",
		"--bare",
		"prompt",
	}

	got := filterArgs(args)
	want := []string{"--allowed", "value", "prompt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterArgs() = %#v, want %#v", got, want)
	}
}

func TestFetchConnectURL(t *testing.T) {
	t.Parallel()

	handlerErrs := make(chan error, 1)
	recordHandlerErr := func(format string, args ...any) {
		select {
		case handlerErrs <- fmt.Errorf(format, args...):
		default:
		}
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			if r.Method != http.MethodPost {
				recordHandlerErr("token method = %q, want %q", r.Method, http.MethodPost)
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-access-token" {
				recordHandlerErr("token authorization = %q, want %q", got, "Bearer test-access-token")
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				recordHandlerErr("read token body: %v", err)
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				recordHandlerErr("parse token body: %v", err)
				http.Error(w, "parse error", http.StatusBadRequest)
				return
			}
			if got := values.Get("client_id"); got != "app_agent-123" {
				recordHandlerErr("client_id = %q, want %q", got, "app_agent-123")
				http.Error(w, "bad client", http.StatusBadRequest)
				return
			}
			if got := values.Get("resource"); got != "mcp-gateway" {
				recordHandlerErr("resource = %q, want %q", got, "mcp-gateway")
				http.Error(w, "bad resource", http.StatusBadRequest)
				return
			}
			if got := values.Get("scope"); got != "gateway:access" {
				recordHandlerErr("scope = %q, want %q", got, "gateway:access")
				http.Error(w, "bad scope", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gateway-token"}`))
		case "/mcp/connect-session":
			if r.Method != http.MethodPost {
				recordHandlerErr("connect method = %q, want %q", r.Method, http.MethodPost)
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer gateway-token" {
				recordHandlerErr("connect authorization = %q, want %q", got, "Bearer gateway-token")
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				recordHandlerErr("connect content-type = %q, want %q", got, "application/json")
				http.Error(w, "bad content-type", http.StatusBadRequest)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				recordHandlerErr("read connect body: %v", err)
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			if got := string(body); got != "{}" {
				recordHandlerErr("connect body = %q, want %q", got, "{}")
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connectUrl":"https://app.kontext.security/providers/connect#handshake=session-123"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	got, err := fetchConnectURL(context.Background(), session, "app_agent-123")
	if err != nil {
		t.Fatalf("fetchConnectURL() error = %v", err)
	}
	select {
	case err := <-handlerErrs:
		t.Fatal(err)
	default:
	}

	want := "https://app.kontext.security/providers/connect#handshake=session-123"
	if got != want {
		t.Fatalf("fetchConnectURL() = %q, want %q", got, want)
	}
}

func TestFetchConnectURLReturnsErrorOnNon200(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gateway-token"}`))
		case "/mcp/connect-session":
			http.Error(w, "boom", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := fetchConnectURL(context.Background(), session, "app_agent-123")
	if err == nil {
		t.Fatal("fetchConnectURL() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("fetchConnectURL() error = %q, want status in message", err)
	}
}

func TestFetchConnectURLReturnsErrorOnEmptyConnectURL(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gateway-token"}`))
		case "/mcp/connect-session":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connectUrl":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := fetchConnectURL(context.Background(), session, "app_agent-123")
	if err == nil {
		t.Fatal("fetchConnectURL() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "missing connectUrl") {
		t.Fatalf("fetchConnectURL() error = %q, want missing connectUrl message", err)
	}
}

func TestFetchConnectURLWithGatewayLoginFallback(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	var tokenExchangeCalls int
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if values.Get("resource") != "mcp-gateway" {
				http.Error(w, "wrong resource", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			tokenExchangeCalls++
			switch tokenExchangeCalls {
			case 1:
				if got := r.Header.Get("Authorization"); got != "Bearer stale-access-token" {
					http.Error(w, "wrong stale authorization", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"Requested scope 'gateway:access' exceeds subject token scopes"}`))
			case 2:
				if got := r.Header.Get("Authorization"); got != "Bearer gateway-login-token" {
					http.Error(w, "wrong gateway-login authorization", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"gateway-exchange-token"}`))
			default:
				http.Error(w, "unexpected token exchange call", http.StatusBadRequest)
				return
			}
		case "/mcp/connect-session":
			if got := r.Header.Get("Authorization"); got != "Bearer gateway-exchange-token" {
				http.Error(w, "wrong gateway authorization", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connectUrl":"https://app.kontext.security/providers/connect#handshake=session-123"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "stale-access-token",
	}

	var loginCalls int
	login := func(ctx context.Context, issuerURL, clientID string, scopes ...string) (*auth.LoginResult, error) {
		loginCalls++
		if issuerURL != server.URL {
			t.Fatalf("login issuerURL = %q, want %q", issuerURL, server.URL)
		}
		if clientID != "app_agent-123" {
			t.Fatalf("login clientID = %q, want %q", clientID, "app_agent-123")
		}
		if got := strings.Join(scopes, " "); got != "gateway:access" {
			t.Fatalf("login scopes = %q, want %q", got, "gateway:access")
		}

		result := &auth.LoginResult{Session: &auth.Session{
			IssuerURL:   server.URL,
			AccessToken: "gateway-login-token",
		}}
		return result, nil
	}

	got, err := fetchConnectURLWithGatewayLoginFallback(
		context.Background(),
		session,
		"app_agent-123",
		login,
	)
	if err != nil {
		t.Fatalf("fetchConnectURLWithGatewayLoginFallback() error = %v", err)
	}
	if loginCalls != 1 {
		t.Fatalf("loginCalls = %d, want 1", loginCalls)
	}
	if tokenExchangeCalls != 2 {
		t.Fatalf("tokenExchangeCalls = %d, want 2", tokenExchangeCalls)
	}
	if session.AccessToken != "stale-access-token" {
		t.Fatalf("session.AccessToken = %q, want stale token unchanged", session.AccessToken)
	}

	want := "https://app.kontext.security/providers/connect#handshake=session-123"
	if got != want {
		t.Fatalf("fetchConnectURLWithGatewayLoginFallback() = %q, want %q", got, want)
	}
}

func TestExchangeCredentialUsesProvidedClientID(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if got := values.Get("client_id"); got != "app_agent-123" {
				http.Error(w, "wrong client_id", http.StatusBadRequest)
				return
			}
			if got := values.Get("resource"); got != "github" {
				http.Error(w, "wrong resource", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"provider-token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	value, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "GITHUB_TOKEN", Provider: "github"},
		"app_agent-123",
	)
	if err != nil {
		t.Fatalf("exchangeCredential() error = %v", err)
	}
	if value != "provider-token" {
		t.Fatalf("exchangeCredential() = %q, want %q", value, "provider-token")
	}
}

func TestIsNotConnectedErrorRecognizesProviderRequired(t *testing.T) {
	t.Parallel()

	if !isNotConnectedError(fmt.Errorf("token exchange failed: provider_required: User has not configured provider 'Linear Stub'")) {
		t.Fatal("expected provider_required to trigger hosted connect fallback")
	}
}

func TestAgentOAuthClientID(t *testing.T) {
	t.Parallel()

	if got := agentOAuthClientID("agent-123"); got != "app_agent-123" {
		t.Fatalf("agentOAuthClientID() = %q, want %q", got, "app_agent-123")
	}
}

func TestResolveCredentialClientID(t *testing.T) {
	t.Parallel()

	if got := resolveCredentialClientID("agent-123", "bootstrap-client"); got != "app_agent-123" {
		t.Fatalf("resolveCredentialClientID() = %q, want %q", got, "app_agent-123")
	}

	if got := resolveCredentialClientID("", "bootstrap-client"); got != "bootstrap-client" {
		t.Fatalf("resolveCredentialClientID() empty agent = %q, want %q", got, "bootstrap-client")
	}
}

// withStubbedAuthSeams overrides the package-level refreshSession and
// clearSession hooks for the duration of a test. The originals are restored
// via t.Cleanup. Tests using this helper must NOT run in parallel because
// the hooks are package globals.
func withStubbedAuthSeams(
	t *testing.T,
	refresh func(context.Context, *auth.Session) (*auth.Session, error),
	clear func() error,
) {
	t.Helper()
	origRefresh, origClear := refreshSession, clearSession
	refreshSession, clearSession = refresh, clear
	t.Cleanup(func() {
		refreshSession, clearSession = origRefresh, origClear
	})
}

func TestNewSessionTokenSource_ReturnsCachedTokenWhenFresh(t *testing.T) {
	withStubbedAuthSeams(t,
		func(_ context.Context, _ *auth.Session) (*auth.Session, error) {
			t.Fatal("refresh should not be called when token is fresh")
			return nil, nil
		},
		func() error { t.Fatal("clear should not be called when token is fresh"); return nil },
	)

	session := &auth.Session{
		AccessToken: "fresh-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	ts := newSessionTokenSource(context.Background(), session)

	tok, err := ts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "fresh-token" {
		t.Fatalf("token = %q, want %q", tok, "fresh-token")
	}
}

func TestNewSessionTokenSource_InvalidGrantClearsSessionAndShortCircuits(t *testing.T) {
	var refreshCalls, clearCalls int
	withStubbedAuthSeams(t,
		func(_ context.Context, _ *auth.Session) (*auth.Session, error) {
			refreshCalls++
			return nil, fmt.Errorf("refresh token: %w", auth.ErrInvalidGrant)
		},
		func() error { clearCalls++; return nil },
	)

	session := &auth.Session{
		AccessToken:  "stale-token",
		RefreshToken: "dead-refresh",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	ts := newSessionTokenSource(context.Background(), session)

	// First call triggers refresh, which fails with invalid_grant.
	_, err := ts()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, auth.ErrInvalidGrant) {
		t.Fatalf("errors.Is(err, ErrInvalidGrant) = false; err = %v", err)
	}
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1", refreshCalls)
	}
	if clearCalls != 1 {
		t.Errorf("clearCalls = %d, want 1", clearCalls)
	}

	// Second call must short-circuit without calling refresh or clear again.
	_, err2 := ts()
	if !errors.Is(err2, auth.ErrInvalidGrant) {
		t.Fatalf("second call: errors.Is(err, ErrInvalidGrant) = false; err = %v", err2)
	}
	if refreshCalls != 1 {
		t.Errorf("after short-circuit, refreshCalls = %d, want 1", refreshCalls)
	}
	if clearCalls != 1 {
		t.Errorf("after short-circuit, clearCalls = %d, want 1", clearCalls)
	}
}

func TestNewSessionTokenSource_TransientErrorDoesNotClearSession(t *testing.T) {
	var refreshCalls, clearCalls int
	withStubbedAuthSeams(t,
		func(_ context.Context, _ *auth.Session) (*auth.Session, error) {
			refreshCalls++
			return nil, fmt.Errorf("refresh token: oauth discovery: network down")
		},
		func() error { clearCalls++; return nil },
	)

	session := &auth.Session{
		AccessToken:  "stale-token",
		RefreshToken: "still-valid",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	ts := newSessionTokenSource(context.Background(), session)

	_, err := ts()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, auth.ErrInvalidGrant) {
		t.Fatalf("transient error should not classify as ErrInvalidGrant; err = %v", err)
	}
	if clearCalls != 0 {
		t.Errorf("clearCalls = %d, want 0 for transient error", clearCalls)
	}

	// Subsequent call should retry refresh (not short-circuit).
	_, _ = ts()
	if refreshCalls != 2 {
		t.Errorf("transient failures should not latch; refreshCalls = %d, want 2", refreshCalls)
	}
}
