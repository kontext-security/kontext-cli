package run

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/auth"
	"github.com/kontext-security/kontext-cli/internal/credential"
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

func TestFetchConnectURLForConnectFlowSkipsLoginWhenNonInteractive(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"Requested scope 'gateway:access' exceeds subject token scopes"}`))
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
		return nil, fmt.Errorf("login should not be called")
	}

	_, err := fetchConnectURLForConnectFlow(
		context.Background(),
		session,
		"app_agent-123",
		false,
		login,
	)
	if err == nil {
		t.Fatal("fetchConnectURLForConnectFlow() error = nil, want non-nil")
	}
	if loginCalls != 0 {
		t.Fatalf("loginCalls = %d, want 0", loginCalls)
	}
	if !needsGatewayAccessReauthentication(err) {
		t.Fatalf("err = %v, want gateway reauthentication failure", err)
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

func TestExchangeCredentialReturnsTypedFailureReason(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider_required","error_description":"User has not configured provider 'Linear Stub'","failure_reason":"disconnected_or_reauth_required","provider_name":"Linear Stub","provider_id":"provider-linear"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "LINEAR_API_KEY", Provider: "linear"},
		"app_agent-123",
	)
	if err == nil {
		t.Fatal("exchangeCredential() error = nil, want non-nil")
	}

	resolutionErr, ok := err.(*credentialResolutionError)
	if !ok {
		t.Fatalf("exchangeCredential() error type = %T, want *credentialResolutionError", err)
	}
	if resolutionErr.Reason != failureDisconnected {
		t.Fatalf("resolutionErr.Reason = %q, want %q", resolutionErr.Reason, failureDisconnected)
	}
}

func TestExchangeCredentialClassifiesLegacyProviderRequired(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider_required","error_description":"User has not configured provider 'Linear Stub'","provider_name":"Linear Stub","provider_id":"provider-linear"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "LINEAR_API_KEY", Provider: "linear"},
		"app_agent-123",
	)
	if err == nil {
		t.Fatal("exchangeCredential() error = nil, want non-nil")
	}

	resolutionErr, ok := err.(*credentialResolutionError)
	if !ok {
		t.Fatalf("exchangeCredential() error type = %T, want *credentialResolutionError", err)
	}
	if resolutionErr.Reason != failureDisconnected {
		t.Fatalf("resolutionErr.Reason = %q, want %q", resolutionErr.Reason, failureDisconnected)
	}
}

func TestExchangeCredentialClassifiesLegacyProviderReauthorizationRequired(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider_reauthorization_required","error_description":"User must reconnect provider 'Linear Stub'","provider_name":"Linear Stub","provider_id":"provider-linear","reauthorization_reason":"missing_scopes"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "LINEAR_API_KEY", Provider: "linear"},
		"app_agent-123",
	)
	if err == nil {
		t.Fatal("exchangeCredential() error = nil, want non-nil")
	}

	resolutionErr, ok := err.(*credentialResolutionError)
	if !ok {
		t.Fatalf("exchangeCredential() error type = %T, want *credentialResolutionError", err)
	}
	if resolutionErr.Reason != failureDisconnected {
		t.Fatalf("resolutionErr.Reason = %q, want %q", resolutionErr.Reason, failureDisconnected)
	}
}

func TestExchangeCredentialClassifiesLegacyInvalidTargetNotAllowed(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"invalid_target","error_description":"Resource 'linear' is not allowed for this application"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "LINEAR_API_KEY", Provider: "linear"},
		"app_agent-123",
	)
	if err == nil {
		t.Fatal("exchangeCredential() error = nil, want non-nil")
	}

	resolutionErr, ok := err.(*credentialResolutionError)
	if !ok {
		t.Fatalf("exchangeCredential() error type = %T, want *credentialResolutionError", err)
	}
	if resolutionErr.Reason != failureDisconnected {
		t.Fatalf("resolutionErr.Reason = %q, want %q", resolutionErr.Reason, failureDisconnected)
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

func TestBuildEnvUsesLiteralValuesAndResolvedPlaceholders(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "shell-token")

	env := buildEnv(
		&credential.TemplateFile{
			Entries: []credential.Entry{
				{EnvVar: "GITHUB_TOKEN", Provider: "github"},
			},
			ExistingValues: map[string]string{
				"GITHUB_TOKEN":   "{{kontext:github}}",
				"LINEAR_API_KEY": "literal-linear-token",
			},
		},
		[]credential.Resolved{
			{
				Entry: credential.Entry{
					EnvVar:   "GITHUB_TOKEN",
					Provider: "github",
				},
				Value: "resolved-github-token",
			},
		},
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "GITHUB_TOKEN=resolved-github-token") {
		t.Fatalf("buildEnv() missing resolved github token: %q", joined)
	}
	if !strings.Contains(joined, "LINEAR_API_KEY=literal-linear-token") {
		t.Fatalf("buildEnv() missing literal linear token: %q", joined)
	}
}

func TestBuildEnvNormalizesQuotedLiteralValues(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"OPENAI_API_KEY": "\"sk-test-token\"",
				"CALLBACK_URL":   "'https://example.com/callback'",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=sk-test-token") {
		t.Fatalf("buildEnv() missing normalized openai token: %q", joined)
	}
	if strings.Contains(joined, "OPENAI_API_KEY=\"sk-test-token\"") {
		t.Fatalf("buildEnv() preserved quoted openai token: %q", joined)
	}
	if !strings.Contains(joined, "CALLBACK_URL=https://example.com/callback") {
		t.Fatalf("buildEnv() missing normalized callback url: %q", joined)
	}
	if strings.Contains(joined, "CALLBACK_URL='https://example.com/callback'") {
		t.Fatalf("buildEnv() preserved quoted callback url: %q", joined)
	}
}

func TestBuildEnvStripsInlineCommentsFromLiteralValues(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"OPENAI_API_KEY": "sk-test-token # production",
				"CALLBACK_URL":   "\"https://example.com/callback\" # main callback",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=sk-test-token") {
		t.Fatalf("buildEnv() missing stripped literal token: %q", joined)
	}
	if strings.Contains(joined, "OPENAI_API_KEY=sk-test-token # production") {
		t.Fatalf("buildEnv() preserved inline comment on token: %q", joined)
	}
	if !strings.Contains(joined, "CALLBACK_URL=https://example.com/callback") {
		t.Fatalf("buildEnv() missing stripped callback url: %q", joined)
	}
	if strings.Contains(joined, "CALLBACK_URL=\"https://example.com/callback\" # main callback") {
		t.Fatalf("buildEnv() preserved inline comment on callback url: %q", joined)
	}
}

func TestBuildEnvPreservesLiteralHashFragmentsWithoutWhitespace(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"CALLBACK_URL": "https://example.com/callback#fragment",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "CALLBACK_URL=https://example.com/callback#fragment") {
		t.Fatalf("buildEnv() lost url fragment: %q", joined)
	}
}

func TestBuildEnvTreatsCommentOnlyRightHandSideAsEmpty(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"OPENAI_API_KEY": " # set later",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=") {
		t.Fatalf("buildEnv() missing empty env assignment: %q", joined)
	}
	if strings.Contains(joined, "OPENAI_API_KEY=# set later") {
		t.Fatalf("buildEnv() preserved comment-only value: %q", joined)
	}
}

type recordingSessionEnder struct {
	sessionID string
	calls     int
}

func (r *recordingSessionEnder) EndSession(_ context.Context, sessionID string) error {
	r.calls++
	r.sessionID = sessionID
	return nil
}

func TestEndManagedSessionEndsTheManagedSession(t *testing.T) {
	t.Parallel()

	client := &recordingSessionEnder{}
	var output bytes.Buffer

	endManagedSession(client, "session-1234567890", &output)

	if client.calls != 1 {
		t.Fatalf("EndSession calls = %d, want 1", client.calls)
	}
	if client.sessionID != "session-1234567890" {
		t.Fatalf("EndSession sessionID = %q, want %q", client.sessionID, "session-1234567890")
	}
	if got := output.String(); !strings.Contains(got, "Session ended") {
		t.Fatalf("output = %q, want session-ended message", got)
	}
}
