// Package mcpserve implements `kontext mcp-serve`: an MCP server that bridges
// tool calls to the Kontext sidecar for governance and tracing.
package mcpserve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/kontext-security/kontext-cli/internal/sidecar"
)

type handler struct {
	agent     string
	socket    string
	sessionID string
}

func newHandler(agent, socket, sessionID string) *handler {
	return &handler{agent: agent, socket: socket, sessionID: sessionID}
}

// invoke runs PreToolUse -> execute -> PostToolUse. Returns the JSON result
// string on allow, or an error containing the deny reason on deny.
func (h *handler) invoke(ctx context.Context, params map[string]any) (string, error) {
	provider, _ := params["provider"].(string)
	action, _ := params["action"].(string)

	allowed, reason, err := h.sendHook(ctx, "PreToolUse", params, nil)
	if err != nil {
		return "", fmt.Errorf("sidecar pre: %w", err)
	}
	if !allowed {
		return "", fmt.Errorf("kontext denied: %s", reason)
	}

	result := map[string]any{
		"status":   "ok",
		"provider": provider,
		"action":   action,
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshal result: %w", err)
	}

	if _, _, err := h.sendHook(ctx, "PostToolUse", params, result); err != nil {
		_ = err
	}
	return string(resultBytes), nil
}

func (h *handler) sendHook(ctx context.Context, eventName string, toolInput, toolResponse map[string]any) (bool, string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", h.socket)
	if err != nil {
		return false, "sidecar unreachable", nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := sidecar.EvaluateRequest{
		Type:      "evaluate",
		Agent:     h.agent,
		HookEvent: eventName,
		ToolName:  "kontext.invoke",
	}
	if toolInput != nil {
		b, err := json.Marshal(toolInput)
		if err != nil {
			return false, "marshal input", err
		}
		req.ToolInput = b
	}
	if toolResponse != nil {
		b, err := json.Marshal(toolResponse)
		if err != nil {
			return false, "marshal response", err
		}
		req.ToolResponse = b
	}

	if err := sidecar.WriteMessage(conn, req); err != nil {
		return false, "write", err
	}
	var res sidecar.EvaluateResult
	if err := sidecar.ReadMessage(conn, &res); err != nil {
		return false, "read", err
	}
	return res.Allowed, res.Reason, nil
}
