package claude

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func TestDecodeHookInputPreservesOptionalMetadata(t *testing.T) {
	t.Parallel()

	modes := []string{
		"default",
		"plan",
		"acceptEdits",
		"auto",
		"dontAsk",
		"bypassPermissions",
		"futureUnknownMode",
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			input, err := json.Marshal(map[string]any{
				"hook_event_name": "PostToolUseFailure",
				"tool_name":       "Bash",
				"tool_input":      map[string]any{"command": "npm test"},
				"tool_use_id":     "toolu_123",
				"cwd":             "/tmp/project",
				"permission_mode": mode,
				"duration_ms":     1234,
				"error":           "command failed",
				"is_interrupt":    true,
			})
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			event, err := (&Claude{}).DecodeHookInput(input)
			if err != nil {
				t.Fatalf("DecodeHookInput() error = %v", err)
			}
			if event.PermissionMode != mode {
				t.Fatalf("PermissionMode = %q, want %q", event.PermissionMode, mode)
			}
			if event.DurationMs == nil || *event.DurationMs != 1234 {
				t.Fatalf("DurationMs = %v, want 1234", event.DurationMs)
			}
			if event.Error != "command failed" {
				t.Fatalf("Error = %q, want command failed", event.Error)
			}
			if event.IsInterrupt == nil || !*event.IsInterrupt {
				t.Fatalf("IsInterrupt = %v, want true", event.IsInterrupt)
			}
		})
	}
}

func TestDecodeHookInputPreservesExplicitFalseInterrupt(t *testing.T) {
	t.Parallel()

	event, err := (&Claude{}).DecodeHookInput([]byte(`{"hook_event_name":"PostToolUseFailure","is_interrupt":false}`))
	if err != nil {
		t.Fatalf("DecodeHookInput() error = %v", err)
	}
	if event.IsInterrupt == nil {
		t.Fatal("IsInterrupt = nil, want explicit false")
	}
	if *event.IsInterrupt {
		t.Fatal("IsInterrupt = true, want false")
	}
}

func TestDecodeHookInputAllowsMissingOptionalMetadata(t *testing.T) {
	t.Parallel()

	event, err := (&Claude{}).DecodeHookInput([]byte(`{"hook_event_name":"PreToolUse"}`))
	if err != nil {
		t.Fatalf("DecodeHookInput() error = %v", err)
	}
	if event.PermissionMode != "" || event.DurationMs != nil || event.Error != "" || event.IsInterrupt != nil {
		t.Fatalf("optional metadata = %+v, want zero values", event)
	}
}

func TestDecodeHookInputAllowsNullOptionalStringMetadata(t *testing.T) {
	t.Parallel()

	event, err := (&Claude{}).DecodeHookInput([]byte(`{"hook_event_name":"PostToolUseFailure","permission_mode":null,"error":null}`))
	if err != nil {
		t.Fatalf("DecodeHookInput() error = %v", err)
	}
	if event.PermissionMode != "" || event.Error != "" {
		t.Fatalf("optional string metadata = %+v, want zero values", event)
	}
}

func TestDecodeHookInputPreservesExplicitZeroDuration(t *testing.T) {
	t.Parallel()

	event, err := (&Claude{}).DecodeHookInput([]byte(`{"hook_event_name":"PostToolUse","duration_ms":0}`))
	if err != nil {
		t.Fatalf("DecodeHookInput() error = %v", err)
	}
	if event.DurationMs == nil {
		t.Fatal("DurationMs = nil, want explicit zero")
	}
	if *event.DurationMs != 0 {
		t.Fatalf("DurationMs = %d, want 0", *event.DurationMs)
	}
}

func TestEncodeAllowOmitsPlaceholderReason(t *testing.T) {
	t.Parallel()

	out, err := (&Claude{}).EncodeAllow(&agent.HookEvent{HookEventName: "PreToolUse"}, "allowed")
	if err != nil {
		t.Fatalf("EncodeAllow() error = %v", err)
	}
	if strings.Contains(string(out), "permissionDecisionReason") {
		t.Fatalf("EncodeAllow() = %s, want no placeholder reason", out)
	}
}

func TestEncodeAllowKeepsMeaningfulReason(t *testing.T) {
	t.Parallel()

	out, err := (&Claude{}).EncodeAllow(&agent.HookEvent{HookEventName: "PreToolUse"}, "Allowed by read-only policy")
	if err != nil {
		t.Fatalf("EncodeAllow() error = %v", err)
	}
	if !strings.Contains(string(out), "Allowed by read-only policy") {
		t.Fatalf("EncodeAllow() = %s, want meaningful reason", out)
	}
}

func TestEncodeDenyKeepsReason(t *testing.T) {
	t.Parallel()

	out, err := (&Claude{}).EncodeDeny(&agent.HookEvent{HookEventName: "PreToolUse"}, "Blocked by policy")
	if err != nil {
		t.Fatalf("EncodeDeny() error = %v", err)
	}
	if !strings.Contains(string(out), "Blocked by policy") {
		t.Fatalf("EncodeDeny() = %s, want deny reason", out)
	}
}
