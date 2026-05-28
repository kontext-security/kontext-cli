package sidecar

import (
	"testing"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestHookResultFromHostedResultMapsProtoDecision(t *testing.T) {
	t.Parallel()

	result := HookResultFromHostedResult(&backend.ProcessHookEventResult{
		Response: &agentv1.ProcessHookEventResponse{
			Decision: agentv1.Decision_DECISION_ASK,
			Reason:   "approval required",
		},
		ReasonCode:     "unsupported_decision",
		RequestID:      "req-123",
		PolicySetEpoch: "epoch-1",
	}, backend.HostedAccessModeEnforce)

	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result.ReasonCode != "unsupported_decision" || result.RequestID != "req-123" || result.Epoch != "epoch-1" {
		t.Fatalf("result metadata = %+v, want hosted metadata preserved", result)
	}
}
