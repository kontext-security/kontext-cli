package backend

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBearerTransportRetries401WithFreshBody(t *testing.T) {
	tokens := []string{"stale", "fresh"}
	tokenCalls := 0
	var bodies []string

	transport := &bearerTransport{
		tokenSource: func(forceRefresh bool) (string, error) {
			if tokenCalls >= len(tokens) {
				t.Fatalf("unexpected token call %d", tokenCalls+1)
			}
			if tokenCalls == 1 && !forceRefresh {
				t.Fatal("second token call must force refresh")
			}
			token := tokens[tokenCalls]
			tokenCalls++
			return token, nil
		},
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			bodies = append(bodies, string(body))

			status := http.StatusOK
			if len(bodies) == 1 {
				status = http.StatusUnauthorized
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.kontext.security", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if tokenCalls != 2 {
		t.Fatalf("token calls = %d, want 2", tokenCalls)
	}
	if len(bodies) != 2 {
		t.Fatalf("bodies = %d, want 2", len(bodies))
	}
	if bodies[0] != "payload" {
		t.Fatalf("first body = %q, want payload", bodies[0])
	}
	if bodies[1] != "payload" {
		t.Fatalf("retry body = %q, want payload", bodies[1])
	}
}

func TestBearerTransportDoesNotRetry401WithNonRewindableBody(t *testing.T) {
	tokenCalls := 0
	var bodies []string

	transport := &bearerTransport{
		tokenSource: func(forceRefresh bool) (string, error) {
			if forceRefresh {
				t.Fatal("non-rewindable request body must not force refresh")
			}
			tokenCalls++
			return "stale", nil
		},
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			bodies = append(bodies, string(body))

			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.kontext.security", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if tokenCalls != 1 {
		t.Fatalf("token calls = %d, want 1", tokenCalls)
	}
	if len(bodies) != 1 {
		t.Fatalf("bodies = %d, want 1", len(bodies))
	}
	if bodies[0] != "payload" {
		t.Fatalf("body = %q, want payload", bodies[0])
	}
}
