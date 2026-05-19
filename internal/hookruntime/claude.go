package hookruntime

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type claudeHookInput struct {
	SessionID        string         `json:"session_id"`
	SessionIDAlt     string         `json:"sessionId"`
	HookEventName    string         `json:"hook_event_name"`
	HookEventNameAlt string         `json:"hookEventName"`
	HookEventLegacy  string         `json:"hook_event"`
	ToolName         string         `json:"tool_name"`
	ToolNameAlt      string         `json:"toolName"`
	ToolInput        map[string]any `json:"tool_input"`
	ToolInputAlt     map[string]any `json:"toolInput"`
	ToolResponse     map[string]any `json:"tool_response"`
	ToolResponseAlt  map[string]any `json:"toolResponse"`
	ToolUseID        string         `json:"tool_use_id"`
	ToolUseIDAlt     string         `json:"toolUseId"`
	ToolUseIDUpper   string         `json:"toolUseID"`
	CWD              string         `json:"cwd"`
	PermissionMode   *string        `json:"permission_mode"`
	DurationMs       *int64         `json:"duration_ms"`
	Error            *string        `json:"error"`
	IsInterrupt      *bool          `json:"is_interrupt"`
}

type claudeHookOutput struct {
	HookSpecificOutput *claudeHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SuppressOutput     bool                      `json:"suppressOutput,omitempty"`
}

type claudeHookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

func DecodeClaudeEvent(input []byte, agentName string) (hook.Event, error) {
	var h claudeHookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("claude: decode hook input: %w", err)
	}
	hookName := firstString(h.HookEventName, h.HookEventNameAlt, h.HookEventLegacy)
	if hookName == "" {
		return hook.Event{}, fmt.Errorf("claude: hook event name missing")
	}
	return hook.Event{
		SessionID:      firstString(h.SessionID, h.SessionIDAlt),
		Agent:          agentName,
		HookName:       hook.HookName(hookName),
		ToolName:       firstString(h.ToolName, h.ToolNameAlt),
		ToolInput:      firstMap(h.ToolInput, h.ToolInputAlt),
		ToolResponse:   firstMap(h.ToolResponse, h.ToolResponseAlt),
		ToolUseID:      firstString(h.ToolUseID, h.ToolUseIDAlt, h.ToolUseIDUpper),
		CWD:            h.CWD,
		PermissionMode: stringPtrValue(h.PermissionMode),
		DurationMs:     h.DurationMs,
		Error:          stringPtrValue(h.Error),
		IsInterrupt:    h.IsInterrupt,
	}, nil
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstMap(values ...map[string]any) map[string]any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func EncodeClaudeResult(hookEventName string, result hook.Result) ([]byte, error) {
	if hook.HookName(hookEventName) != hook.HookPreToolUse {
		return json.Marshal(claudeHookOutput{SuppressOutput: true})
	}

	permissionDecision := string(result.Decision)
	if permissionDecision != string(hook.DecisionAllow) &&
		permissionDecision != string(hook.DecisionAsk) &&
		permissionDecision != string(hook.DecisionDeny) {
		permissionDecision = string(hook.DecisionDeny)
	}
	reason := result.ClaudeReason()
	if permissionDecision == "allow" && strings.EqualFold(strings.TrimSpace(reason), "allowed") {
		reason = ""
	}
	out := claudeHookOutput{
		HookSpecificOutput: &claudeHookSpecificOutput{
			HookEventName:            hookEventName,
			PermissionDecision:       permissionDecision,
			PermissionDecisionReason: reason,
			UpdatedInput:             result.UpdatedInput,
		},
		SuppressOutput: result.UpdatedInput != nil,
	}
	return json.Marshal(out)
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
