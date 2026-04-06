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

	agentv1 "github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1/agentv1connect"
)

// Client wraps the ConnectRPC AgentService client.
type Client struct {
	rpc agentv1connect.AgentServiceClient
}

// NewClient creates a ConnectRPC client authenticated with the user's bearer token.
func NewClient(baseURL, accessToken string) *Client {
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &bearerTransport{token: accessToken, base: http.DefaultTransport},
	}

	return &Client{
		rpc: agentv1connect.NewAgentServiceClient(httpClient, baseURL),
	}
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

// IngestEvent sends a single hook event via the ProcessHookEvent stream.
func (c *Client) IngestEvent(ctx context.Context, req *agentv1.ProcessHookEventRequest) error {
	stream := c.rpc.ProcessHookEvent(ctx)
	if err := stream.Send(req); err != nil {
		return fmt.Errorf("send hook event: %w", err)
	}
	if err := stream.CloseRequest(); err != nil {
		return err
	}
	if resp, err := stream.Receive(); err == nil {
		_ = resp
	}
	return stream.CloseResponse()
}

// bearerTransport injects the user's OIDC token into every request.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}
