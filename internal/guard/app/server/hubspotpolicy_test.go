package server

import (
	"context"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hubspotpolicy"
	"github.com/kontext-security/kontext-cli/internal/providerpolicy"
)

type staticSnapshotProvider struct {
	snapshot providerpolicy.Snapshot
	status   providerpolicy.Status
	loaded   bool
}

func (p staticSnapshotProvider) CurrentSnapshot() (providerpolicy.Snapshot, providerpolicy.Status, bool) {
	return p.snapshot, p.status, p.loaded
}

func hubspotTestSnapshot(mode string, rules ...providerpolicy.Rule) providerpolicy.Snapshot {
	return providerpolicy.Snapshot{
		SchemaVersion:  hubspotpolicy.SchemaVersionV1,
		OrganizationID: "org_test",
		ProviderKey:    "hubspot",
		Mode:           mode,
		Epoch:          2,
		Hash:           "hash-2",
		Rules:          rules,
	}
}

// The exact tool-name shape Claude Cowork emits for the HubSpot connector,
// observed live: the server segment is the connector-instance uuid.
func hubspotWriteEvent() risk.HookEvent {
	return risk.HookEvent{
		SessionID:     "session-1",
		HookEventName: "PreToolUse",
		ToolName:      "mcp__5c56899e-3e6c-4803-85ca-ff1912393966__manage_crm_objects",
		ToolInput: map[string]any{
			"updateRequest": map[string]any{
				"objects": []any{map[string]any{"objectType": "deals", "id": "813518832889"}},
			},
		},
	}
}

func TestDecideHookRecordsHubspotDryRunWithoutBlocking(t *testing.T) {
	denyResource := "deals"
	denyAction := "hubspot.object.write"
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		ProviderPolicies: []ProviderPolicyBinding{HubspotPolicyBinding(staticSnapshotProvider{
			snapshot: hubspotTestSnapshot(providerpolicy.ModeObserve,
				providerpolicy.Rule{ID: "rule-deny-deals", Layer: providerpolicy.LayerOrg, SubjectID: "org_test", ResourceID: &denyResource, ActionName: &denyAction, Effect: providerpolicy.EffectDeny},
			),
			loaded: true,
		})},
	})

	decision, err := provider.DecideHook(context.Background(), hubspotWriteEvent())
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	// Observe mode: the policy would deny, but the runtime decision is
	// untouched — nothing is ever blocked.
	if decision.Decision != risk.DecisionAllow {
		t.Fatalf("Decision = %v, want allow in observe mode", decision.Decision)
	}
	if len(decision.ProviderPolicy) != 1 || decision.ProviderPolicy[0].Provider != "hubspot" {
		t.Fatalf("ProviderPolicy = %+v, want one hubspot group", decision.ProviderPolicy)
	}
	evaluations := decision.ProviderPolicy[0].Evaluations
	if len(evaluations) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(evaluations))
	}
	evaluation := evaluations[0]
	if evaluation.Result != providerpolicy.EffectDeny || evaluation.Request.Resource != "deals" {
		t.Fatalf("evaluation = %+v, want would-deny on deals", evaluation)
	}
	if evaluation.Request.Action != "hubspot.object.write" {
		t.Fatalf("action = %q", evaluation.Request.Action)
	}
}

func TestDecideHookEvaluatesBothProvidersIndependently(t *testing.T) {
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		ProviderPolicies: []ProviderPolicyBinding{
			GithubPolicyBinding(staticSnapshotProvider{
				snapshot: providerpolicy.Snapshot{
					SchemaVersion:  "github-policy-snapshot-v2",
					OrganizationID: "org_test",
					ProviderKey:    "github",
					Mode:           providerpolicy.ModeObserve,
					Epoch:          1,
					Hash:           "hash-1",
					Rules:          []providerpolicy.Rule{{ID: "r-gh", Layer: providerpolicy.LayerOrg, SubjectID: "org_test", Effect: providerpolicy.EffectAllow}},
				},
				loaded: true,
			}),
			HubspotPolicyBinding(staticSnapshotProvider{
				snapshot: hubspotTestSnapshot(providerpolicy.ModeObserve,
					providerpolicy.Rule{ID: "r-hs", Layer: providerpolicy.LayerOrg, SubjectID: "org_test", Effect: providerpolicy.EffectAllow},
				),
				loaded: true,
			}),
		},
	})

	// A HubSpot MCP call must produce hubspot evaluations only — the GitHub
	// classifier does not fire on it, and vice versa.
	decision, err := provider.DecideHook(context.Background(), hubspotWriteEvent())
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if len(decision.ProviderPolicy) != 1 || decision.ProviderPolicy[0].Provider != "hubspot" {
		t.Fatalf("ProviderPolicy = %+v, want hubspot only", decision.ProviderPolicy)
	}

	githubEvent := risk.HookEvent{
		SessionID:     "session-1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git push https://github.com/acme/api.git main"},
	}
	decision, err = provider.DecideHook(context.Background(), githubEvent)
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if len(decision.ProviderPolicy) != 1 || decision.ProviderPolicy[0].Provider != "github" {
		t.Fatalf("ProviderPolicy = %+v, want github only", decision.ProviderPolicy)
	}
}
