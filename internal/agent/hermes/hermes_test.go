package hermes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestDecodePreToolCall(t *testing.T) {
	t.Parallel()

	input := []byte(`{
		"hook_event_name": "pre_tool_call",
		"tool_name": "terminal",
		"tool_input": {"command": "cat .env"},
		"session_id": "sess_123",
		"cwd": "/tmp/project",
		"extra": {"tool_call_id": "call_123"}
	}`)

	event, err := DecodeEvent(input)
	if err != nil {
		t.Fatalf("DecodeEvent() error = %v", err)
	}
	if event.Agent != "hermes" ||
		event.HookName != hook.HookPreToolUse ||
		event.ToolName != "Bash" ||
		event.SessionID != "sess_123" ||
		event.ToolUseID != "call_123" ||
		event.CWD != "/tmp/project" {
		t.Fatalf("event = %+v, want normalized Hermes pre-tool event", event)
	}
	if event.ToolInput["command"] != "cat .env" {
		t.Fatalf("tool input = %+v, want command", event.ToolInput)
	}
}

func TestDecodePostToolCallPreservesResultMetadata(t *testing.T) {
	t.Parallel()

	input := []byte(`{
		"hook_event_name": "post_tool_call",
		"tool_name": "read_file",
		"tool_input": {"path": "README.md"},
		"session_id": "sess_123",
		"cwd": "/tmp/project",
		"extra": {
			"tool_call_id": "call_123",
			"result": "{\"ok\":true}",
			"duration_ms": 42,
			"error": "command failed",
			"is_interrupt": false
		}
	}`)

	event, err := DecodeEvent(input)
	if err != nil {
		t.Fatalf("DecodeEvent() error = %v", err)
	}
	if event.HookName != hook.HookPostToolUse || event.ToolName != "Read" {
		t.Fatalf("event = %+v, want normalized post-tool event", event)
	}
	if got := event.ToolResponse["result"]; got != `{"ok":true}` {
		t.Fatalf("ToolResponse[result] = %#v, want raw result", got)
	}
	if event.DurationMs == nil || *event.DurationMs != 42 {
		t.Fatalf("DurationMs = %v, want 42", event.DurationMs)
	}
	if event.Error != "command failed" {
		t.Fatalf("Error = %q, want command failed", event.Error)
	}
	if event.IsInterrupt == nil || *event.IsInterrupt {
		t.Fatalf("IsInterrupt = %v, want explicit false", event.IsInterrupt)
	}
}

func TestDecodeAcceptsCamelCaseAndTopLevelMetadata(t *testing.T) {
	t.Parallel()

	input := []byte(`{
		"hookEventName": "postToolCall",
		"toolName": "write_file",
		"toolInput": {"path": "README.md", "content": "hello"},
		"sessionId": "sess_123",
		"cwd": "/tmp/project",
		"toolUseID": "call_123",
		"result": "wrote file",
		"durationMs": 7,
		"error": "write warning",
		"isInterrupt": true
	}`)

	event, err := DecodeEvent(input)
	if err != nil {
		t.Fatalf("DecodeEvent() error = %v", err)
	}
	if event.HookName != hook.HookPostToolUse ||
		event.ToolName != "Write" ||
		event.SessionID != "sess_123" ||
		event.ToolUseID != "call_123" ||
		event.CWD != "/tmp/project" {
		t.Fatalf("event = %+v, want camelCase Hermes event metadata", event)
	}
	if event.ToolInput["content"] != "hello" {
		t.Fatalf("ToolInput = %+v, want camelCase tool input", event.ToolInput)
	}
	if got := event.ToolResponse["result"]; got != "wrote file" {
		t.Fatalf("ToolResponse[result] = %#v, want top-level result", got)
	}
	if event.DurationMs == nil || *event.DurationMs != 7 {
		t.Fatalf("DurationMs = %v, want 7", event.DurationMs)
	}
	if event.Error != "write warning" {
		t.Fatalf("Error = %q, want write warning", event.Error)
	}
	if event.IsInterrupt == nil || !*event.IsInterrupt {
		t.Fatalf("IsInterrupt = %v, want explicit true", event.IsInterrupt)
	}
}

func TestDecodeRejectsUnsupportedHook(t *testing.T) {
	t.Parallel()

	_, err := DecodeEvent([]byte(`{"hook_event_name":"pre_llm_call"}`))
	if err == nil {
		t.Fatal("DecodeEvent() error = nil, want unsupported hook error")
	}
	if !strings.Contains(err.Error(), "unsupported hook event") {
		t.Fatalf("DecodeEvent() error = %v, want unsupported hook event", err)
	}
}

func TestDecodeRejectsMissingHookName(t *testing.T) {
	t.Parallel()

	_, err := DecodeEvent([]byte(`{"tool_name":"terminal"}`))
	if err == nil {
		t.Fatal("DecodeEvent() error = nil, want missing hook event name")
	}
	if !strings.Contains(err.Error(), "hook event name missing") {
		t.Fatalf("DecodeEvent() error = %v, want missing hook event name", err)
	}
}

func TestEncodeAllowsWithNoopOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeResult(
		hook.Event{HookName: hook.HookPreToolUse},
		hook.Result{Decision: hook.DecisionAllow, Reason: "allowed"},
	)
	if err != nil {
		t.Fatalf("EncodeResult() error = %v", err)
	}
	if string(out) != "{}" {
		t.Fatalf("EncodeResult() = %s, want empty Hermes response", out)
	}
}

func TestEncodeBlocksDenyAndAsk(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		result     hook.Result
		wantReason string
	}{
		{
			name:       "deny",
			result:     hook.Result{Decision: hook.DecisionDeny, Reason: "blocked by policy"},
			wantReason: "blocked by policy",
		},
		{
			name:       "ask",
			result:     hook.Result{Decision: hook.DecisionAsk, Reason: "approval required", RequestID: "req-123"},
			wantReason: "approval required Request ID: req-123",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := EncodeResult(hook.Event{HookName: hook.HookPreToolUse}, tt.result)
			if err != nil {
				t.Fatalf("EncodeResult() error = %v", err)
			}
			var got hookOutput
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("Unmarshal(%s) error = %v", out, err)
			}
			if got.Action != "block" || got.Message != tt.wantReason {
				t.Fatalf("output = %+v, want block with reason %q", got, tt.wantReason)
			}
		})
	}
}

func TestEncodeDoesNotBlockNonBlockingHooks(t *testing.T) {
	t.Parallel()

	out, err := EncodeResult(
		hook.Event{HookName: hook.HookPostToolUse},
		hook.Result{Decision: hook.DecisionDeny, Reason: "telemetry only"},
	)
	if err != nil {
		t.Fatalf("EncodeResult() error = %v", err)
	}
	if string(out) != "{}" {
		t.Fatalf("EncodeResult() = %s, want empty Hermes response", out)
	}
}

func TestNormalizeToolName(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"terminal":   "Bash",
		"shell":      "Bash",
		"read_file":  "Read",
		"write_file": "Write",
		"patch":      "Edit",
		"web_search": "web_search",
	}
	for input, want := range cases {
		if got := normalizeToolName(input); got != want {
			t.Fatalf("normalizeToolName(%q) = %q, want %q", input, got, want)
		}
	}
}
