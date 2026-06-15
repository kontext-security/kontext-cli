package server

import (
	"context"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type staticGithubPolicy struct {
	snapshot githubpolicy.Snapshot
	status   githubpolicy.Status
	loaded   bool
}

func (p staticGithubPolicy) CurrentSnapshot() (githubpolicy.Snapshot, githubpolicy.Status, bool) {
	return p.snapshot, p.status, p.loaded
}

func githubTestSnapshot(mode string, rules ...githubpolicy.Rule) githubpolicy.Snapshot {
	return githubpolicy.Snapshot{
		SchemaVersion:  githubpolicy.SchemaVersion,
		OrganizationID: "org_test",
		ProviderKey:    "github",
		Mode:           mode,
		Epoch:          5,
		Hash:           "hash-5",
		Rules:          rules,
	}
}

func githubPushEvent() risk.HookEvent {
	return risk.HookEvent{
		SessionID:     "session-1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		// The github.com mention makes the classification self-contained; no
		// git context is needed from the (nonexistent) cwd.
		ToolInput: map[string]any{"command": "git push https://github.com/acme/api.git main"},
	}
}

func TestDecideHookRecordsGithubDryRunWithoutBlocking(t *testing.T) {
	denyResource := "acme/api"
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		GithubPolicy: staticGithubPolicy{
			snapshot: githubTestSnapshot(githubpolicy.ModeObserve,
				githubpolicy.Rule{ID: "rule-deny", Layer: githubpolicy.LayerOrg, SubjectID: "org_test", ResourceID: &denyResource, Effect: githubpolicy.EffectDeny},
			),
			loaded: true,
		},
	})

	decision, err := provider.DecideHook(context.Background(), githubPushEvent())
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	// Observe mode: the policy would deny, but the runtime decision is
	// untouched — nothing is ever blocked.
	if decision.Decision != risk.DecisionAllow {
		t.Fatalf("Decision = %v, want allow in observe mode", decision.Decision)
	}
	if len(decision.GithubPolicy) != 1 {
		t.Fatalf("GithubPolicy evaluations = %d, want 1", len(decision.GithubPolicy))
	}
	evaluation := decision.GithubPolicy[0]
	if evaluation.Result != githubpolicy.EffectDeny || evaluation.ReasonCode != githubpolicy.ReasonCodeDeny {
		t.Fatalf("evaluation = %+v, want would-deny", evaluation)
	}
	if evaluation.Request.Action != "github.repo.write" || evaluation.Request.Resource != "acme/api" {
		t.Fatalf("classified request = %+v", evaluation.Request)
	}
}

func TestDecideHookEnforceModeDeniesBeforeJudge(t *testing.T) {
	denyResource := "acme/api"
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		GithubPolicy: staticGithubPolicy{
			snapshot: githubTestSnapshot(githubpolicy.ModeEnforce,
				githubpolicy.Rule{ID: "rule-deny", Layer: githubpolicy.LayerOrg, SubjectID: "org_test", ResourceID: &denyResource, Effect: githubpolicy.EffectDeny},
			),
			loaded: true,
		},
	})

	decision, err := provider.DecideHook(context.Background(), githubPushEvent())
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if decision.Decision != risk.DecisionDeny {
		t.Fatalf("Decision = %v, want deny when the snapshot directs enforcement", decision.Decision)
	}
	if decision.ReasonCode != githubpolicy.ReasonCodeDeny {
		t.Fatalf("ReasonCode = %q", decision.ReasonCode)
	}
}

func TestDecideHookUnknownModeIsTreatedAsObserve(t *testing.T) {
	denyResource := "acme/api"
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		GithubPolicy: staticGithubPolicy{
			snapshot: githubTestSnapshot("enforce-later-maybe",
				githubpolicy.Rule{ID: "rule-deny", Layer: githubpolicy.LayerOrg, SubjectID: "org_test", ResourceID: &denyResource, Effect: githubpolicy.EffectDeny},
			),
			loaded: true,
		},
	})

	decision, err := provider.DecideHook(context.Background(), githubPushEvent())
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if decision.Decision != risk.DecisionAllow {
		t.Fatalf("Decision = %v, want allow: only an explicit enforce mode may block", decision.Decision)
	}
	if len(decision.GithubPolicy) != 1 {
		t.Fatalf("evaluations = %d, want dry-run recorded regardless of mode", len(decision.GithubPolicy))
	}
}

func TestDecideHookNonGithubEventsCarryNoEvaluations(t *testing.T) {
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		GithubPolicy: staticGithubPolicy{
			snapshot: githubTestSnapshot(githubpolicy.ModeObserve,
				githubpolicy.Rule{ID: "rule-allow", Layer: githubpolicy.LayerOrg, SubjectID: "org_test", Effect: githubpolicy.EffectAllow},
			),
			loaded: true,
		},
	})

	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{
		SessionID:     "session-1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "ls -la"},
	})
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if len(decision.GithubPolicy) != 0 {
		t.Fatalf("evaluations = %+v, want none for non-GitHub activity", decision.GithubPolicy)
	}
}

func TestDecideHookWithoutSnapshotProviderIsUnchanged(t *testing.T) {
	provider := NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{})
	decision, err := provider.DecideHook(context.Background(), githubPushEvent())
	if err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if decision.Decision != risk.DecisionAllow || len(decision.GithubPolicy) != 0 {
		t.Fatalf("decision = %+v, want plain allow with no evaluations", decision)
	}
}
