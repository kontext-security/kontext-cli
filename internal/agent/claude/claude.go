package claude

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func init() {
	agent.Register(&Claude{})
}

type Claude struct{}

func (c *Claude) Name() string { return "claude" }

type hookInput struct {
	SessionID      string         `json:"session_id"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   map[string]any `json:"tool_response"`
	ToolUseID      string         `json:"tool_use_id"`
	CWD            string         `json:"cwd"`
	PermissionMode *string        `json:"permission_mode"`
	DurationMs     *int64         `json:"duration_ms"`
	Error          *string        `json:"error"`
	IsInterrupt    *bool          `json:"is_interrupt"`
}

func (c *Claude) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	var h hookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return nil, fmt.Errorf("claude: decode hook input: %w", err)
	}
	return &agent.HookEvent{
		SessionID:      h.SessionID,
		HookEventName:  h.HookEventName,
		ToolName:       h.ToolName,
		ToolInput:      h.ToolInput,
		ToolResponse:   h.ToolResponse,
		ToolUseID:      h.ToolUseID,
		CWD:            h.CWD,
		PermissionMode: stringValue(h.PermissionMode),
		DurationMs:     h.DurationMs,
		Error:          stringValue(h.Error),
		IsInterrupt:    h.IsInterrupt,
	}, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

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
			PermissionDecisionReason: allowReason(reason),
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

func allowReason(reason string) string {
	if strings.EqualFold(strings.TrimSpace(reason), "allowed") {
		return ""
	}
	return reason
}
