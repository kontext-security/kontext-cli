package run

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

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
