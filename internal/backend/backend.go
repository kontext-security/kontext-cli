// Package backend provides the ConnectRPC client for the Kontext AgentService.
// Authenticates with the user's OIDC bearer token from `kontext login`.
// No client secrets, no client_credentials grant.
package backend

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/gen/kontext/agent/v1/agentv1connect"
)

// TokenSource returns a valid access token, refreshing if necessary.
// If forceRefresh is true, the source must obtain a new token regardless of
// whether the cached one appears valid (used for retry-on-401).
type TokenSource func(forceRefresh bool) (string, error)

// Client wraps the ConnectRPC AgentService client.
type Client struct {
	rpc agentv1connect.AgentServiceClient
}

// NewClient creates a ConnectRPC client that fetches a fresh token per request.
func NewClient(baseURL string, ts TokenSource) *Client {
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &bearerTransport{tokenSource: ts, base: http.DefaultTransport},
	}

	return &Client{
		rpc: agentv1connect.NewAgentServiceClient(httpClient, baseURL),
	}
}

// StaticToken returns a TokenSource that always returns the same token.
// Useful for tests or short-lived commands.
func StaticToken(token string) TokenSource {
	return func(_ bool) (string, error) { return token, nil }
}

// BaseURL returns the API base URL from env or default.
func BaseURL() string {
	if v := os.Getenv("KONTEXT_API_URL"); v != "" {
		return v
	}
	return "https://api.kontext.security"
}

// CreateSession creates a governed agent session.
func (c *Client) CreateSession(ctx context.Context, req *agentv1.CreateSessionRequest) (*agentv1.CreateSessionResponse, error) {
	resp, err := c.rpc.CreateSession(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("CreateSession: %w", err)
	}
	return resp.Msg, nil
}

// BootstrapCli prepares the shared CLI application for env template sync.
func (c *Client) BootstrapCli(ctx context.Context, req *agentv1.BootstrapCliRequest) (*agentv1.BootstrapCliResponse, error) {
	resp, err := c.rpc.BootstrapCli(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("BootstrapCli: %w", err)
	}
	return resp.Msg, nil
}

// Heartbeat keeps a session alive.
func (c *Client) Heartbeat(ctx context.Context, sessionID string) error {
	_, err := c.rpc.Heartbeat(ctx, connect.NewRequest(&agentv1.HeartbeatRequest{
		SessionId: sessionID,
	}))
	return err
}

// EndSession terminates a session.
func (c *Client) EndSession(ctx context.Context, sessionID string) error {
	_, err := c.rpc.EndSession(ctx, connect.NewRequest(&agentv1.EndSessionRequest{
		SessionId: sessionID,
	}))
	return err
}

// IngestEvent sends a single hook event via the ProcessHookEvent unary RPC.
func (c *Client) IngestEvent(ctx context.Context, req *agentv1.ProcessHookEventRequest) error {
	_, err := c.rpc.ProcessHookEvent(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("ProcessHookEvent: %w", err)
	}
	return nil
}

// bearerTransport fetches a fresh token for every outgoing request.
// On 401, it forces a token refresh and retries once.
type bearerTransport struct {
	tokenSource TokenSource
	base        http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.tokenSource(false)
	if err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}

	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	// Retry once with a forced refresh on 401 — the cached token may be
	// stale even though IsExpired() said it was fine (server-side revocation,
	// clock skew, Hydra TTL mismatch, etc.).
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		token, err = t.tokenSource(true)
		if err != nil {
			return nil, fmt.Errorf("token refresh (retry): %w", err)
		}
		r2 := req.Clone(req.Context())
		r2.Header.Set("Authorization", "Bearer "+token)
		return t.base.RoundTrip(r2)
	}

	return resp, nil
}
