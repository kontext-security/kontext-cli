package hermes

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func init() {
	agent.Register(&Hermes{})
}

type Hermes struct{}

func (h *Hermes) Name() string { return "hermes" }

func (h *Hermes) Aliases() []string { return []string{"hermes-agent"} }

func (h *Hermes) DecodeHookInput(input []byte) (hook.Event, error) {
	return DecodeEvent(input)
}

func (h *Hermes) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return EncodeResult(event, result)
}

type HookInput struct {
	HookEventName      string         `json:"hook_event_name"`
	HookEventNameCamel string         `json:"hookEventName"`
	ToolName           string         `json:"tool_name"`
	ToolNameCamel      string         `json:"toolName"`
	ToolInput          map[string]any `json:"tool_input"`
	ToolInputCamel     map[string]any `json:"toolInput"`
	SessionID          string         `json:"session_id"`
	SessionIDCamel     string         `json:"sessionId"`
	CWD                string         `json:"cwd"`
	Extra              map[string]any `json:"extra"`
	ToolCallID         string         `json:"tool_call_id"`
	ToolUseID          string         `json:"tool_use_id"`
	ToolUseIDCamel     string         `json:"toolUseID"`
	DurationMs         any            `json:"duration_ms"`
	DurationMsCamel    any            `json:"durationMs"`
	Error              any            `json:"error"`
	IsInterrupt        any            `json:"is_interrupt"`
	IsInterruptCamel   any            `json:"isInterrupt"`
	Result             any            `json:"result"`
}

type hookOutput struct {
	Action  string `json:"action,omitempty"`
	Message string `json:"message,omitempty"`
}

func DecodeEvent(input []byte) (hook.Event, error) {
	var h HookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("hermes: decode hook input: %w", err)
	}
	hookEventName := firstNonEmpty(h.HookEventName, h.HookEventNameCamel)
	hookName, ok := mapHookName(hookEventName)
	if !ok {
		if strings.TrimSpace(hookEventName) == "" {
			return hook.Event{}, fmt.Errorf("hermes: hook event name missing")
		}
		return hook.Event{}, fmt.Errorf("hermes: unsupported hook event %q", hookEventName)
	}

	metadata := h.metadata()
	event := hook.Event{
		SessionID:    firstNonEmpty(h.SessionID, h.SessionIDCamel),
		Agent:        "hermes",
		HookName:     hookName,
		ToolName:     normalizeToolName(firstNonEmpty(h.ToolName, h.ToolNameCamel)),
		ToolInput:    firstMap(h.ToolInput, h.ToolInputCamel),
		ToolUseID:    stringFromExtra(metadata, "tool_call_id", "tool_use_id", "toolUseID"),
		CWD:          h.CWD,
		ToolResponse: toolResponseFromExtra(metadata),
	}
	if duration, ok := int64FromExtra(metadata, "duration_ms", "durationMs"); ok {
		event.DurationMs = &duration
	}
	if errText := stringFromExtra(metadata, "error"); errText != "" {
		event.Error = errText
	}
	if interrupted, ok := boolFromExtra(metadata, "is_interrupt", "isInterrupt"); ok {
		event.IsInterrupt = &interrupted
	}
	return event, nil
}

func (h HookInput) metadata() map[string]any {
	metadata := map[string]any{}
	for key, value := range h.Extra {
		metadata[key] = value
	}
	for key, value := range map[string]any{
		"tool_call_id": h.ToolCallID,
		"tool_use_id":  h.ToolUseID,
		"toolUseID":    h.ToolUseIDCamel,
		"duration_ms":  h.DurationMs,
		"durationMs":   h.DurationMsCamel,
		"error":        h.Error,
		"is_interrupt": h.IsInterrupt,
		"isInterrupt":  h.IsInterruptCamel,
		"result":       h.Result,
	} {
		if isZeroMetadataValue(value) {
			continue
		}
		metadata[key] = value
	}
	return metadata
}

func EncodeResult(event hook.Event, result hook.Result) ([]byte, error) {
	if !event.HookName.CanBlock() || !result.Blocking() {
		return []byte("{}"), nil
	}

	return json.Marshal(hookOutput{
		Action:  "block",
		Message: blockMessage(result),
	})
}

func mapHookName(value string) (hook.HookName, bool) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "")) {
	case "pretoolcall":
		return hook.HookPreToolUse, true
	case "posttoolcall":
		return hook.HookPostToolUse, true
	default:
		return "", false
	}
}

func normalizeToolName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "terminal", "shell", "bash":
		return "Bash"
	case "read_file", "read":
		return "Read"
	case "write_file", "write":
		return "Write"
	case "patch", "edit", "edit_file":
		return "Edit"
	default:
		return value
	}
}

func toolResponseFromExtra(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	if result, ok := extra["result"]; ok {
		return map[string]any{"result": result}
	}
	return nil
}

func blockMessage(result hook.Result) string {
	if reason := result.ClaudeReason(); strings.TrimSpace(reason) != "" {
		return reason
	}
	return "Blocked by Kontext access policy."
}

func stringFromExtra(extra map[string]any, keys ...string) string {
	if extra == nil {
		return ""
	}
	for _, key := range keys {
		value, ok := extra[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			return typed
		case json.Number:
			return typed.String()
		}
	}
	return ""
}

func int64FromExtra(extra map[string]any, keys ...string) (int64, bool) {
	if extra == nil {
		return 0, false
	}
	for _, key := range keys {
		value, ok := extra[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int64(typed), true
		case json.Number:
			parsed, err := typed.Int64()
			return parsed, err == nil
		case int64:
			return typed, true
		case int:
			return int64(typed), true
		default:
			return 0, false
		}
	}
	return 0, false
}

func boolFromExtra(extra map[string]any, keys ...string) (bool, bool) {
	if extra == nil {
		return false, false
	}
	for _, key := range keys {
		value, ok := extra[key]
		if !ok {
			continue
		}
		typed, ok := value.(bool)
		return typed, ok
	}
	return false, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
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

func isZeroMetadataValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	default:
		return false
	}
}
