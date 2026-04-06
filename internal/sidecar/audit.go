// internal/sidecar/audit.go
package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// AuditEvent is sent to the backend after each policy decision.
type AuditEvent struct {
	ToolName  string `json:"toolName"`
	Action    string `json:"action"` // "allow" or "deny"
	Reason    string `json:"reason"`
	SessionID string `json:"sessionId"`
	Timestamp string `json:"timestamp"`
}

// Auditor sends MCP events to the backend asynchronously.
type Auditor struct {
	baseURL     string
	accessToken string
	ch          chan AuditEvent
}

// NewAuditor creates an auditor with a buffered channel.
func NewAuditor(baseURL string, accessToken string) *Auditor {
	return &Auditor{
		baseURL:     baseURL,
		accessToken: accessToken,
		ch:          make(chan AuditEvent, 100),
	}
}

// Start begins draining the audit channel. Stops when ctx is cancelled.
func (a *Auditor) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-a.ch:
				a.send(ctx, event)
			}
		}
	}()
}

// Record queues an audit event. Non-blocking; drops if buffer is full.
func (a *Auditor) Record(toolName string, allowed bool, reason string, sessionID string) {
	action := "allow"
	if !allowed {
		action = "deny"
	}
	event := AuditEvent{
		ToolName:  toolName,
		Action:    action,
		Reason:    reason,
		SessionID: sessionID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	select {
	case a.ch <- event:
	default:
		// Buffer full, drop event rather than blocking
	}
}

func (a *Auditor) send(ctx context.Context, event AuditEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := a.baseURL + "/api/v1/mcp-events"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
