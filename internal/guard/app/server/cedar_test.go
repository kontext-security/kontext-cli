package server

import (
	"context"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type staticCedarSnapshots struct{ snapshot cedarpolicy.Snapshot }

func (s staticCedarSnapshots) Current() cedarpolicy.Snapshot { return s.snapshot }

type staticHookPolicy struct{ decision risk.RiskDecision }

func (p staticHookPolicy) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	return p.decision, nil
}

func TestCedarObservePreservesCurrentAuthorityAndRecordsDecision(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny, Reason: "current deny", ReasonCode: "current_deny", RiskEvent: risk.RiskEvent{Decision: risk.DecisionDeny}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}})

	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != "current_deny" {
		t.Fatalf("effective decision = %#v, want unchanged current authority", decision)
	}
	if decision.Cedar == nil || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("Cedar evidence = %#v, want observe", decision.Cedar)
	}
	if decision.Cedar.Mapping.DerivedCedarAction != cedareval.DerivedCedarActionAllow {
		t.Fatalf("derived action = %q, want allow", decision.Cedar.Mapping.DerivedCedarAction)
	}
	if decision.Cedar.Mapping.EffectiveExecutionAction != cedareval.EffectiveExecutionActionDeny {
		t.Fatalf("effective Cedar mapping = %q, want current deny", decision.Cedar.Mapping.EffectiveExecutionAction)
	}
}

func TestCedarObserveClassifiesContextConversionFailure(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, `@id("permit") permit(principal, action, resource);`)
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}})

	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"bad": make(chan struct{})}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.Mapping.EvaluationReasonCode != cedareval.ReasonRequestConversionFailed {
		t.Fatalf("evaluation reason = %q, want conversion failure", decision.Cedar.Mapping.EvaluationReasonCode)
	}
	if decision.Decision != risk.DecisionAllow {
		t.Fatal("observe failure changed current authority")
	}
}

func TestCedarObserveRecordsUnresolvedPrincipal(t *testing.T) {
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StatePrincipalUnavailable}})
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStatePrincipalUnresolved || decision.Cedar.Mapping.EvaluationPrincipal != nil {
		t.Fatalf("mapping = %#v, want unresolved principal without identity", decision.Cedar.Mapping)
	}
}

func cedarTestDeployment(t *testing.T, mode cedareval.RolloutMode, policy string) cedarpolicy.Deployment {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{EntityType: cedareval.PrincipalEntityType, EntityID: "user@example.com"}
	hash := cedareval.ComputePolicyHash(policy)
	identity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{ResponseVersion: 1, RequestContractVersion: 1, PolicyHash: hash, RolloutMode: string(mode), EvaluationPrincipal: principal})
	if err != nil {
		t.Fatal(err)
	}
	return cedarpolicy.Deployment{ResponseVersion: 1, RequestContractVersion: 1, PolicyHash: hash, RolloutMode: mode, EvaluationPrincipal: principal, PolicyText: policy, DeploymentIdentity: identity}
}
