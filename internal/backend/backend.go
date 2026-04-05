// Package backend provides the ConnectRPC client for the Kontext AgentService.
package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1/agentv1connect"
)

// Config holds backend connection parameters.
type Config struct {
	BaseURL      string `json:"baseUrl"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// LoadConfig reads backend configuration from env vars or ~/.kontext/config.json.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		BaseURL:      envOr("KONTEXT_API_URL", "https://api.kontext.security"),
		ClientID:     os.Getenv("KONTEXT_CLIENT_ID"),
		ClientSecret: os.Getenv("KONTEXT_CLIENT_SECRET"),
	}

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		if fileCfg, err := loadConfigFile(); err == nil && fileCfg != nil {
			if cfg.ClientID == "" {
				cfg.ClientID = fileCfg.ClientID
			}
			if cfg.ClientSecret == "" {
				cfg.ClientSecret = fileCfg.ClientSecret
			}
		}
	}

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("KONTEXT_CLIENT_ID and KONTEXT_CLIENT_SECRET required (set via env or ~/.kontext/config.json)")
	}

	return cfg, nil
}

func loadConfigFile() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(home, ".kontext", "config.json"))
	if err != nil {
		return nil, err
	}
	var cfg Config
	return &cfg, json.Unmarshal(data, &cfg)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Client wraps the ConnectRPC AgentService client with token management.
type Client struct {
	rpc    agentv1connect.AgentServiceClient
	config *Config
	token  string
	tokenExp time.Time
	mu     sync.Mutex
}

// NewClient creates a ConnectRPC client for the Kontext AgentService.
func NewClient(config *Config) *Client {
	httpClient := &http.Client{Timeout: 30 * time.Second}

	c := &Client{config: config}

	// Wrap the HTTP client with an auth interceptor
	authClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &authTransport{client: c, base: httpClient.Transport},
	}

	c.rpc = agentv1connect.NewAgentServiceClient(
		authClient,
		config.BaseURL,
	)

	return c
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

// IngestEvent sends a single hook event to the backend.
func (c *Client) IngestEvent(ctx context.Context, req *agentv1.HookEventRequest) error {
	stream := c.rpc.ProcessHookEvent(ctx)
	if err := stream.Send(req); err != nil {
		return fmt.Errorf("send hook event: %w", err)
	}
	// For now, send one event per stream. The sidecar will hold a persistent
	// stream open once the full bidirectional flow is wired.
	if err := stream.CloseRequest(); err != nil {
		return err
	}
	// Read the response
	if resp, err := stream.Receive(); err == nil {
		_ = resp // decision logged server-side
	}
	return stream.CloseResponse()
}

// --- Token management ---

func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}

	// Discover token endpoint
	resp, err := http.Get(c.config.BaseURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()

	var meta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("decode discovery: %w", err)
	}

	// Client credentials flow
	req, err := http.NewRequestWithContext(ctx, "POST", meta.TokenEndpoint,
		strings.NewReader("grant_type=client_credentials&scope=management:all+mcp:invoke"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)

	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		return "", fmt.Errorf("token request: %s", tokenResp.Status)
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		return "", err
	}

	c.token = tokenData.AccessToken
	if tokenData.ExpiresIn > 0 {
		c.tokenExp = time.Now().Add(time.Duration(tokenData.ExpiresIn-60) * time.Second)
	} else {
		c.tokenExp = time.Now().Add(50 * time.Minute)
	}

	return c.token, nil
}

// authTransport injects the bearer token into every request.
type authTransport struct {
	client *Client
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.client.getToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
