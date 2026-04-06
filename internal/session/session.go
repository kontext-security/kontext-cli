package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Manager manages an agent session lifecycle.
type Manager struct {
	id          string
	baseURL     string
	accessToken string
}

// ID returns the agent session ID.
func (m *Manager) ID() string { return m.id }

// Create registers a new agent session with the backend.
func Create(ctx context.Context, baseURL string, accessToken string) (*Manager, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	body, _ := json.Marshal(map[string]any{})
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/v1/agent-sessions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create agent session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("create agent session: HTTP %d", resp.StatusCode)
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode session response: %w", err)
	}

	return &Manager{
		id:          result.ID,
		baseURL:     baseURL,
		accessToken: accessToken,
	}, nil
}

// StartHeartbeat begins sending periodic heartbeats. Stops when ctx is cancelled.
func (m *Manager) StartHeartbeat(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.heartbeat(ctx)
			}
		}
	}()
}

func (m *Manager) heartbeat(ctx context.Context) {
	url := m.baseURL + "/api/v1/agent-sessions/" + m.id + "/heartbeat"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+m.accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// Disconnect ends the agent session. Uses a short timeout to avoid blocking shutdown.
func (m *Manager) Disconnect(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := m.baseURL + "/api/v1/agent-sessions/" + m.id + "/disconnect"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+m.accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
