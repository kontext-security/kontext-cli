package hookruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

const codexSessionPrefix = "codex-"

type codexHookInput struct {
	SessionID      string          `json:"session_id"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	ToolUseID      string          `json:"tool_use_id"`
	CWD            string          `json:"cwd"`
	PermissionMode *string         `json:"permission_mode"`
	Prompt         *string         `json:"prompt"`
	Source         *string         `json:"source"`
}

type codexHookOutput struct {
	Continue           *bool                    `json:"continue,omitempty"`
	StopReason         string                   `json:"stopReason,omitempty"`
	SystemMessage      string                   `json:"systemMessage,omitempty"`
	Decision           string                   `json:"decision,omitempty"`
	Reason             string                   `json:"reason,omitempty"`
	HookSpecificOutput *codexHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type codexHookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	Decision                 *codexDecision `json:"decision,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

type codexDecision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

func DecodeCodexEvent(input []byte, agentName string) (hook.Event, error) {
	var h codexHookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("codex: decode hook input: %w", err)
	}
	if h.HookEventName == "" {
		return hook.Event{}, fmt.Errorf("codex: hook event name missing")
	}
	hookName := hook.HookName(h.HookEventName)
	if !codexSupportedHook(hookName) {
		return hook.Event{}, fmt.Errorf("codex: unsupported hook event %q", h.HookEventName)
	}

	toolInput, err := normalizeCodexToolInput(h)
	if err != nil {
		return hook.Event{}, err
	}
	return hook.Event{
		SessionID:      codexSessionID(h.SessionID),
		Agent:          agentName,
		HookName:       hookName,
		ToolName:       h.ToolName,
		ToolInput:      toolInput,
		ToolResponse:   normalizeToolResponse(h.ToolResponse),
		ToolUseID:      h.ToolUseID,
		CWD:            h.CWD,
		PermissionMode: stringPtrValue(h.PermissionMode),
	}, nil
}

func EncodeCodexResult(hookEventName string, result hook.Result) ([]byte, error) {
	hookName := hook.HookName(hookEventName)
	if !codexSupportedHook(hookName) {
		return nil, fmt.Errorf("codex: unsupported hook event %q", hookEventName)
	}

	reason := codexMeaningfulReason(result)
	if hookName == hook.HookPreToolUse {
		return encodeCodexPreToolUseResult(hookEventName, result, reason)
	}
	if hookName == hook.HookPermissionRequest {
		return encodeCodexPermissionRequestResult(hookEventName, result)
	}
	return encodeCodexNonPreToolUseResult(hookEventName, result, reason)
}

func encodeCodexPreToolUseResult(hookEventName string, result hook.Result, reason string) ([]byte, error) {
	if result.Decision != hook.DecisionAllow {
		return json.Marshal(codexHookOutput{
			HookSpecificOutput: &codexHookSpecificOutput{
				HookEventName:            hookEventName,
				PermissionDecision:       string(hook.DecisionDeny),
				PermissionDecisionReason: result.ClaudeReason(),
			},
		})
	}

	if result.UpdatedInput == nil && reason == "" {
		return json.Marshal(codexHookOutput{})
	}
	out := codexHookOutput{
		HookSpecificOutput: &codexHookSpecificOutput{
			HookEventName:     hookEventName,
			AdditionalContext: reason,
			UpdatedInput:      result.UpdatedInput,
		},
	}
	if result.UpdatedInput != nil {
		out.HookSpecificOutput.PermissionDecision = string(hook.DecisionAllow)
	}
	return json.Marshal(out)
}

func encodeCodexPermissionRequestResult(hookEventName string, result hook.Result) ([]byte, error) {
	if codexShouldDeclinePermissionRequest(result) {
		return json.Marshal(codexHookOutput{})
	}
	if result.Decision != hook.DecisionAllow {
		return json.Marshal(codexHookOutput{
			HookSpecificOutput: &codexHookSpecificOutput{
				HookEventName: hookEventName,
				Decision: &codexDecision{
					Behavior: string(hook.DecisionDeny),
					Message:  result.ClaudeReason(),
				},
			},
		})
	}
	if !codexCanAllowPermissionRequest(result) {
		return json.Marshal(codexHookOutput{})
	}
	return json.Marshal(codexHookOutput{
		HookSpecificOutput: &codexHookSpecificOutput{
			HookEventName: hookEventName,
			Decision: &codexDecision{
				Behavior: string(hook.DecisionAllow),
			},
		},
	})
}

func codexShouldDeclinePermissionRequest(result hook.Result) bool {
	if strings.EqualFold(strings.TrimSpace(result.Mode), "observe") {
		return true
	}
	reason := strings.TrimSpace(result.Reason)
	return strings.HasPrefix(reason, "Kontext observe mode: would deny;") ||
		strings.HasPrefix(reason, "Kontext observe mode: would allow;")
}

func codexCanAllowPermissionRequest(result hook.Result) bool {
	mode := strings.TrimSpace(result.Mode)
	return mode == "" || strings.EqualFold(mode, "local") || strings.EqualFold(mode, "enforce")
}

func encodeCodexNonPreToolUseResult(hookEventName string, result hook.Result, reason string) ([]byte, error) {
	if result.Decision == hook.DecisionDeny {
		switch hook.HookName(hookEventName) {
		case hook.HookPostToolUse, hook.HookUserPromptSubmit:
			return json.Marshal(codexHookOutput{
				Decision: "block",
				Reason:   result.ClaudeReason(),
			})
		case hook.HookSessionStart:
			cont := false
			return json.Marshal(codexHookOutput{
				Continue:   &cont,
				StopReason: result.ClaudeReason(),
			})
		}
	}

	if reason == "" {
		return json.Marshal(codexHookOutput{})
	}
	return json.Marshal(codexHookOutput{
		HookSpecificOutput: &codexHookSpecificOutput{
			HookEventName:     hookEventName,
			AdditionalContext: reason,
		},
	})
}

func codexSupportedHook(hookName hook.HookName) bool {
	switch hookName {
	case hook.HookSessionStart,
		hook.HookPreToolUse,
		hook.HookPermissionRequest,
		hook.HookPostToolUse,
		hook.HookPostToolUseFailed,
		hook.HookSessionEnd,
		hook.HookUserPromptSubmit:
		return true
	default:
		return false
	}
}

func codexSessionID(sessionID string) string {
	if sessionID == "" || strings.HasPrefix(sessionID, codexSessionPrefix) {
		return sessionID
	}
	return codexSessionPrefix + sessionID
}

func normalizeCodexToolInput(h codexHookInput) (map[string]any, error) {
	toolInput, err := normalizeCodexJSONMap(h.ToolInput)
	if err != nil {
		return nil, err
	}
	if h.HookEventName == hook.HookUserPromptSubmit.String() && h.Prompt != nil {
		if toolInput == nil {
			toolInput = map[string]any{}
		}
		toolInput["prompt"] = *h.Prompt
	}
	if h.HookEventName == hook.HookSessionStart.String() && h.Source != nil {
		if toolInput == nil {
			toolInput = map[string]any{}
		}
		toolInput["source"] = *h.Source
	}
	return toolInput, nil
}

func normalizeCodexJSONMap(raw json.RawMessage) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	var obj map[string]any
	if err := decodeUseNumber(trimmed, &obj); err == nil {
		return obj, nil
	}
	var value any
	if err := decodeUseNumber(trimmed, &value); err != nil {
		return nil, fmt.Errorf("codex: decode JSON value: %w", err)
	}
	return map[string]any{"value": value}, nil
}

func codexMeaningfulReason(result hook.Result) string {
	reason := strings.TrimSpace(result.Reason)
	switch {
	case reason == "":
		return ""
	case strings.EqualFold(reason, "allowed"):
		return ""
	case strings.EqualFold(reason, "telemetry allowed"):
		return ""
	case strings.EqualFold(reason, "async telemetry event recorded"):
		return ""
	case strings.HasPrefix(reason, "Kontext observe mode: would allow;"):
		return ""
	default:
		return reason
	}
}
