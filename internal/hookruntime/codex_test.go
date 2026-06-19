package hookruntime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestDecodeCodexEventPreToolUse(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"abc123",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_use_id":"call_123",
		"tool_input":{"command":"npm test","id":9007199254740993},
		"cwd":"/tmp/project",
		"permission_mode":"default"
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.SessionID != "codex-abc123" {
		t.Fatalf("SessionID = %q, want prefixed id", event.SessionID)
	}
	if event.Agent != "codex" ||
		event.HookName != hook.HookPreToolUse ||
		event.ToolName != "Bash" ||
		event.ToolUseID != "call_123" ||
		event.CWD != "/tmp/project" ||
		event.PermissionMode != "default" {
		t.Fatalf("event = %+v, want decoded metadata", event)
	}
	if event.ToolInput["command"] != "npm test" {
		t.Fatalf("ToolInput[command] = %v, want npm test", event.ToolInput["command"])
	}
	if num, ok := event.ToolInput["id"].(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("ToolInput[id] = %v (%T), want json.Number", event.ToolInput["id"], event.ToolInput["id"])
	}
}

func TestDecodeCodexEventPreservesExistingSessionPrefix(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{"session_id":"codex-abc123","hook_event_name":"SessionStart","source":"startup"}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.SessionID != "codex-abc123" {
		t.Fatalf("SessionID = %q, want unchanged prefixed id", event.SessionID)
	}
}

func TestDecodeCodexEventSessionStartPreservesSource(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"SessionStart",
		"source":"resume",
		"tool_input":{"reason":"startup"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.HookName != hook.HookSessionStart {
		t.Fatalf("HookName = %q, want SessionStart", event.HookName)
	}
	if event.ToolInput["source"] != "resume" {
		t.Fatalf("ToolInput[source] = %v, want resume", event.ToolInput["source"])
	}
	if event.ToolInput["reason"] != "startup" {
		t.Fatalf("ToolInput[reason] = %v, want startup", event.ToolInput["reason"])
	}
}

func TestDecodeCodexEventUserPromptSubmitPreservesPrompt(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"UserPromptSubmit",
		"prompt":"ship it",
		"tool_input":{"model":"gpt-5-codex"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.HookName != hook.HookUserPromptSubmit {
		t.Fatalf("HookName = %q, want UserPromptSubmit", event.HookName)
	}
	if event.ToolInput["prompt"] != "ship it" {
		t.Fatalf("ToolInput[prompt] = %v, want prompt", event.ToolInput["prompt"])
	}
	if event.ToolInput["model"] != "gpt-5-codex" {
		t.Fatalf("ToolInput[model] = %v, want gpt-5-codex", event.ToolInput["model"])
	}
}

func TestDecodeCodexEventTopLevelPromptTakesPrecedence(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"UserPromptSubmit",
		"prompt":"top-level prompt",
		"tool_input":{"prompt":"nested prompt"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.ToolInput["prompt"] != "top-level prompt" {
		t.Fatalf("ToolInput[prompt] = %v, want top-level prompt", event.ToolInput["prompt"])
	}
}

func TestDecodeCodexEventLifecycleHooks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantEvent hook.HookName
	}{
		{
			name:      "post tool use failure",
			input:     `{"session_id":"s1","hook_event_name":"PostToolUseFailure","tool_name":"Bash"}`,
			wantEvent: hook.HookPostToolUseFailed,
		},
		{
			name:      "session end",
			input:     `{"session_id":"s1","hook_event_name":"SessionEnd","tool_input":{"reason":"exit"}}`,
			wantEvent: hook.HookSessionEnd,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event, err := DecodeCodexEvent([]byte(tt.input), "codex")
			if err != nil {
				t.Fatalf("DecodeCodexEvent() error = %v", err)
			}
			if event.HookName != tt.wantEvent {
				t.Fatalf("HookName = %q, want %q", event.HookName, tt.wantEvent)
			}
		})
	}
}

func TestDecodeCodexEventPostToolUsePreservesArrayResponse(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"PostToolUse",
		"tool_name":"mcp__fs__read",
		"tool_response":[{"id":9007199254740993}]
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	content, ok := event.ToolResponse["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("ToolResponse[content] = %v (%T), want one item", event.ToolResponse["content"], event.ToolResponse["content"])
	}
	id := content[0].(map[string]any)["id"]
	if num, ok := id.(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("response id = %v (%T), want json.Number", id, id)
	}
}

func TestDecodeCodexEventPermissionRequest(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"PermissionRequest",
		"tool_name":"Bash",
		"tool_input":{"command":"sudo make install"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.HookName != hook.HookPermissionRequest || !event.HookName.CanBlock() {
		t.Fatalf("HookName = %q, want blocking PermissionRequest", event.HookName)
	}
	if event.ToolInput["command"] != "sudo make install" {
		t.Fatalf("ToolInput[command] = %v, want command", event.ToolInput["command"])
	}
}

func TestDecodeCodexEventRejectsUnsupportedEvent(t *testing.T) {
	t.Parallel()

	_, err := DecodeCodexEvent([]byte(`{"hook_event_name":"UnsupportedHook"}`), "codex")
	if err == nil {
		t.Fatal("DecodeCodexEvent() error = nil, want unsupported event error")
	}
	if !strings.Contains(err.Error(), "unsupported hook event") {
		t.Fatalf("DecodeCodexEvent() error = %v, want unsupported hook event", err)
	}
}

func TestEncodeCodexPermissionRequestDeny(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PermissionRequest", hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Blocked by policy",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	var got codexHookOutput
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.HookSpecificOutput == nil || got.HookSpecificOutput.Decision == nil {
		t.Fatalf("EncodeCodexResult() = %s, want hookSpecificOutput.decision", out)
	}
	if got.HookSpecificOutput.Decision.Behavior != "deny" {
		t.Fatalf("behavior = %q, want deny", got.HookSpecificOutput.Decision.Behavior)
	}
	if got.HookSpecificOutput.Decision.Message != "Blocked by policy" {
		t.Fatalf("message = %q, want reason", got.HookSpecificOutput.Decision.Message)
	}
}

func TestEncodeCodexPermissionRequestAllow(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"", "local", "enforce"} {
		mode := mode
		t.Run("mode="+mode, func(t *testing.T) {
			t.Parallel()

			out, err := EncodeCodexResult("PermissionRequest", hook.Result{
				Decision: hook.DecisionAllow,
				Mode:     mode,
				Reason:   "allowed",
			})
			if err != nil {
				t.Fatalf("EncodeCodexResult() error = %v", err)
			}
			var got codexHookOutput
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if got.HookSpecificOutput == nil || got.HookSpecificOutput.Decision == nil {
				t.Fatalf("EncodeCodexResult() = %s, want hookSpecificOutput.decision", out)
			}
			if got.HookSpecificOutput.Decision.Behavior != "allow" {
				t.Fatalf("behavior = %q, want allow", got.HookSpecificOutput.Decision.Behavior)
			}
			if got.HookSpecificOutput.Decision.Message != "" {
				t.Fatalf("message = %q, want empty allow message", got.HookSpecificOutput.Decision.Message)
			}
		})
	}
}

func TestEncodeCodexPermissionRequestDeclinesObserveDecisions(t *testing.T) {
	t.Parallel()

	tests := []hook.Result{
		{Decision: hook.DecisionAllow, Mode: "observe", Reason: "Kontext observe mode: would deny; blocked"},
		{Decision: hook.DecisionAllow, Mode: "observe", Reason: "Kontext observe mode: would allow; allowed"},
		{Decision: hook.DecisionAllow, Reason: "Kontext observe mode: would deny; blocked"},
		{Decision: hook.DecisionAllow, Mode: "no_policy", Reason: "backend observed a block"},
	}
	for _, result := range tests {
		result := result
		t.Run(result.Reason+" "+result.Mode, func(t *testing.T) {
			t.Parallel()

			out, err := EncodeCodexResult("PermissionRequest", result)
			if err != nil {
				t.Fatalf("EncodeCodexResult() error = %v", err)
			}
			if got := string(out); got != "{}" {
				t.Fatalf("EncodeCodexResult() = %s, want empty object", got)
			}
		})
	}
}

func TestEncodeCodexPreToolUseDenyOmitsSuppressOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PreToolUse", hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Blocked by policy",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"permissionDecision":"deny"`) || !strings.Contains(text, "Blocked by policy") {
		t.Fatalf("EncodeCodexResult() = %s, want deny decision and reason", text)
	}
	if strings.Contains(text, "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", text)
	}
}

func TestEncodeCodexPreToolUseAllowUpdatedInputOmitsSuppressOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PreToolUse", hook.Result{
		Decision:     hook.DecisionAllow,
		Reason:       "allowed",
		UpdatedInput: map[string]any{"command": "echo rewritten"},
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"permissionDecision":"allow"`) || !strings.Contains(text, `"updatedInput"`) {
		t.Fatalf("EncodeCodexResult() = %s, want allow decision and updatedInput", text)
	}
	if strings.Contains(text, "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", text)
	}
}

func TestEncodeCodexAllowNoOpOmitsSuppressOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PostToolUse", hook.Result{
		Decision: hook.DecisionAllow,
		Reason:   "async telemetry event recorded",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	if got := string(out); got != "{}" {
		t.Fatalf("EncodeCodexResult() = %s, want empty object", got)
	}
	if strings.Contains(string(out), "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", out)
	}
}

func TestEncodeCodexUserPromptSubmitDenyBlocks(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("UserPromptSubmit", hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Ask for confirmation first",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"decision":"block"`) || !strings.Contains(text, "Ask for confirmation first") {
		t.Fatalf("EncodeCodexResult() = %s, want block decision", text)
	}
	if strings.Contains(text, "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", text)
	}
}

func TestEncodeCodexRejectsUnsupportedEvent(t *testing.T) {
	t.Parallel()

	_, err := EncodeCodexResult("UnsupportedHook", hook.Result{Decision: hook.DecisionAllow})
	if err == nil {
		t.Fatal("EncodeCodexResult() error = nil, want unsupported event error")
	}
}
