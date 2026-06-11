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

type HostedAccessMode string

const (
	HostedAccessModeDisabled HostedAccessMode = "disabled"
	HostedAccessModeNoPolicy HostedAccessMode = "no_policy"
	HostedAccessModeEnforce  HostedAccessMode = "enforce"
)

type BootstrapCliResult struct {
	Response       *agentv1.BootstrapCliResponse
	AccessMode     HostedAccessMode
	PolicySetEpoch string
}

type ProcessHookEventResult struct {
	Response       *agentv1.ProcessHookEventResponse
	ReasonCode     string
	RequestID      string
	AccessMode     HostedAccessMode
	PolicySetEpoch string
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
func (c *Client) BootstrapCli(ctx context.Context, req *agentv1.BootstrapCliRequest) (*BootstrapCliResult, error) {
	resp, err := c.rpc.BootstrapCli(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("BootstrapCli: %w", err)
	}
	mode := HostedAccessMode(resp.Msg.GetAccessMode())
	if mode == "" {
		mode = HostedAccessMode(resp.Header().Get("x-kontext-access-mode"))
	}
	if mode == "" {
		return nil, fmt.Errorf("BootstrapCli: missing hosted access mode")
	}
	switch mode {
	case HostedAccessModeDisabled, HostedAccessModeNoPolicy, HostedAccessModeEnforce:
	default:
		return nil, fmt.Errorf("BootstrapCli: unknown hosted access mode %q", mode)
	}
	return &BootstrapCliResult{
		Response:       resp.Msg,
		AccessMode:     mode,
		PolicySetEpoch: firstNonEmpty(resp.Msg.GetPolicySetEpoch(), resp.Header().Get("x-kontext-policy-set-epoch")),
	}, nil
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

// ProcessHookEvent sends a single hook event via the ProcessHookEvent unary RPC.
func (c *Client) ProcessHookEvent(ctx context.Context, req *agentv1.ProcessHookEventRequest) (*ProcessHookEventResult, error) {
	resp, err := c.rpc.ProcessHookEvent(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("ProcessHookEvent: %w", err)
	}
	mode := HostedAccessMode(resp.Header().Get("x-kontext-access-mode"))
	if mode == "" {
		mode = HostedAccessMode(resp.Msg.GetAccessMode())
	}
	switch mode {
	case "", HostedAccessModeDisabled, HostedAccessModeNoPolicy, HostedAccessModeEnforce:
	default:
		return nil, fmt.Errorf("ProcessHookEvent: unknown hosted access mode %q", mode)
	}
	reasonCode := resp.Msg.GetReasonCode()
	if reasonCode == "" {
		reasonCode = resp.Header().Get("x-kontext-access-reason-code")
	}
	requestID := resp.Msg.GetRequestId()
	if requestID == "" {
		requestID = resp.Header().Get("x-kontext-access-request-id")
	}
	policySetEpoch := resp.Msg.GetPolicySetEpoch()
	if policySetEpoch == "" {
		policySetEpoch = resp.Header().Get("x-kontext-policy-set-epoch")
	}
	return &ProcessHookEventResult{
		Response:       resp.Msg,
		ReasonCode:     reasonCode,
		RequestID:      requestID,
		AccessMode:     mode,
		PolicySetEpoch: policySetEpoch,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
		if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
			return resp, nil
		}
		resp.Body.Close()
		token, err = t.tokenSource(true)
		if err != nil {
			return nil, fmt.Errorf("token refresh (retry): %w", err)
		}
		r2 := req.Clone(req.Context())
		if req.GetBody != nil {
			r2.Body, err = req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("reset request body for 401 retry: %w", err)
			}
		}
		r2.Header.Set("Authorization", "Bearer "+token)
		return t.base.RoundTrip(r2)
	}

	return resp, nil
}
