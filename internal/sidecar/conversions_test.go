package sidecar

import (
	"encoding/json"
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
		ReasonCode:     "needs_approval",
		RequestID:      "req-123",
		PolicySetEpoch: "epoch-1",
	}, backend.HostedAccessModeEnforce)

	if result.Decision != hook.DecisionAsk {
		t.Fatalf("decision = %q, want ask", result.Decision)
	}
	if result.ReasonCode != "needs_approval" || result.RequestID != "req-123" || result.Epoch != "epoch-1" {
		t.Fatalf("result metadata = %+v, want hosted metadata preserved", result)
	}
}

func TestMarshalMapSanitizesUnsupportedTypesAndReturnsError(t *testing.T) {
	t.Parallel()

	data, err := marshalMap(map[string]any{
		"fn":     func() {},
		"nested": map[any]any{1: func() {}},
	})
	if err == nil {
		t.Fatal("marshalMap() err = nil, want error for unsupported types")
	}
	var out map[string]any
	if unmarshalErr := json.Unmarshal(data, &out); unmarshalErr != nil {
		t.Fatalf("marshalMap() JSON = %s: %v", data, unmarshalErr)
	}
	if out["fn"] != "<unsupported:func()>" {
		t.Fatalf("fn = %v, want unsupported placeholder", out["fn"])
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %T, want map", out["nested"])
	}
	if nested["1"] != "<unsupported:func()>" {
		t.Fatalf("nested[1] = %v, want unsupported placeholder", nested["1"])
	}
}
