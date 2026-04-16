package claude

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

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
