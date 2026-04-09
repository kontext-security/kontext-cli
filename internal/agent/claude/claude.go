// Package claude implements the agent adapter for Claude Code.
package claude

import (
	"encoding/json"
	"fmt"

	"github.com/kontext-dev/kontext-cli/internal/agent"
)

func init() {
	agent.Register(&Claude{})
}

// Claude implements the agent.Agent interface for Claude Code.
type Claude struct{}

func (c *Claude) Name() string { return "claude" }

// hookInput is the JSON structure Claude Code sends on hook stdin.
type hookInput struct {
	SessionID      string         `json:"session_id"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   map[string]any `json:"tool_response"`
	ToolUseID      string         `json:"tool_use_id"`
	CWD            string         `json:"cwd"`
	PermissionMode string         `json:"permission_mode"`
}

func (c *Claude) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	var h hookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return nil, fmt.Errorf("claude: decode hook input: %w", err)
	}
	return &agent.HookEvent{
		SessionID:     h.SessionID,
		HookEventName: h.HookEventName,
		ToolName:      h.ToolName,
		ToolInput:     h.ToolInput,
		ToolResponse:  h.ToolResponse,
		ToolUseID:     h.ToolUseID,
		CWD:           h.CWD,
	}, nil
}

// hookOutput is the JSON structure Claude Code expects on hook stdout.
type hookOutput struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

func (c *Claude) EncodeAllow(event *agent.HookEvent, reason string) ([]byte, error) {
	out := hookOutput{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            event.HookEventName,
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}

func (c *Claude) EncodeDeny(event *agent.HookEvent, reason string) ([]byte, error) {
	out := hookOutput{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            event.HookEventName,
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}
