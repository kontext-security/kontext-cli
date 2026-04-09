package run

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-dev/kontext-cli/internal/auth"
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			recordHandlerErr("method = %q, want %q", r.Method, http.MethodPost)
			http.Error(w, "bad method", http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/mcp/connect-session" {
			recordHandlerErr("path = %q, want %q", r.URL.Path, "/mcp/connect-session")
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-access-token" {
			recordHandlerErr("authorization = %q, want %q", got, "Bearer test-access-token")
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			recordHandlerErr("content-type = %q, want %q", got, "application/json")
			http.Error(w, "bad content-type", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			recordHandlerErr("read body: %v", err)
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		if got := string(body); got != "{}" {
			recordHandlerErr("body = %q, want %q", got, "{}")
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connectUrl":"https://app.kontext.security/providers/connect#handshake=session-123"}`))
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	got, err := fetchConnectURL(context.Background(), session)
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := fetchConnectURL(context.Background(), session)
	if err == nil {
		t.Fatal("fetchConnectURL() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("fetchConnectURL() error = %q, want status in message", err)
	}
}

func TestFetchConnectURLReturnsErrorOnEmptyConnectURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connectUrl":""}`))
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := fetchConnectURL(context.Background(), session)
	if err == nil {
		t.Fatal("fetchConnectURL() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "missing connectUrl") {
		t.Fatalf("fetchConnectURL() error = %q, want missing connectUrl message", err)
	}
}
