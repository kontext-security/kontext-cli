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

type countingHookPolicy struct {
	decision risk.RiskDecision
	calls    int
}

func (p *countingHookPolicy) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	p.calls++
	return p.decision, nil
}

func TestCedarObservePreservesCurrentAuthorityAndRecordsDecision(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny, Reason: "current deny", ReasonCode: "current_deny", RiskEvent: risk.RiskEvent{Decision: risk.DecisionDeny}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}}, false)

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
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, false)

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
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StatePrincipalUnavailable}}, false)
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStatePrincipalUnresolved || decision.Cedar.Mapping.EvaluationPrincipal != nil {
		t.Fatalf("mapping = %#v, want unresolved principal without identity", decision.Cedar.Mapping)
	}
}

func TestCedarEnforceIsSingularAuthority(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny, ReasonCode: "legacy_deny"}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}}, true)

	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 {
		t.Fatalf("previous evaluator calls = %d, want zero after cutover", current.calls)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != string(cedareval.ReasonPermit) {
		t.Fatalf("decision = %#v, want Cedar allow", decision)
	}
}

func TestCedarEnforceDeniesAskWithoutApprovalChannel(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("ask-write") @ask("prompt") permit(principal, action, resource == Kontext::Tool::"Write");`)
	current := &countingHookPolicy{}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, true)
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Write", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonAskUnavailable) {
		t.Fatalf("decision = %#v, want ask fail-closed", decision)
	}
}

func TestCedarEnforceFailsClosedWithoutFallback(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	tests := []struct {
		name     string
		snapshot cedarpolicy.Snapshot
	}{
		{name: "expired cache", snapshot: cedarpolicy.Snapshot{LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{Stale: true, Expired: true}}},
		{name: "invalid cache", snapshot: cedarpolicy.Snapshot{Status: cedarpolicy.CacheStatus{Invalid: true, Stale: true, Expired: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: tt.snapshot}, true)
			decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if current.calls != 0 || decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEnforcementNotReady) {
				t.Fatalf("calls = %d decision = %#v, want no fallback and deny", current.calls, decision)
			}
		})
	}
}

func TestCedarExplicitDisableReturnsAuthorityToCurrentEvaluator(t *testing.T) {
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StateDisabled}}, true)
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("calls = %d decision = %#v, want explicit rollback", current.calls, decision)
	}
}

func TestCedarEnforceDoesNotFallbackOnNonRollbackResponseStates(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	states := []cedarpolicy.State{
		cedarpolicy.StatePrincipalUnavailable,
		cedarpolicy.StateUnsupportedVersion,
		cedarpolicy.StateUnauthorized,
	}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
				LastKnownGood: &deployment,
				State:         state,
			}}, true)
			decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if current.calls != 0 || decision.Decision != risk.DecisionDeny {
				t.Fatalf("calls = %d decision = %#v, want retained Cedar authority and deny", current.calls, decision)
			}
		})
	}
}

func TestCedarEnforceFailsClosedWithoutLastKnownGood(t *testing.T) {
	states := []cedarpolicy.State{
		"",
		cedarpolicy.StatePrincipalUnavailable,
		cedarpolicy.StateUnsupportedVersion,
		cedarpolicy.StateUnauthorized,
	}
	for _, state := range states {
		name := string(state)
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: state}}, true)
			decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if current.calls != 0 || decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEnforcementNotReady) {
				t.Fatalf("calls = %d decision = %#v, want fail-closed Cedar authority", current.calls, decision)
			}
		})
	}
}

func TestCedarConfiguredObserveKeepsCurrentAuthority(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, `@id("forbid-all") forbid(principal, action, resource);`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, true)
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("calls = %d decision = %#v, want current observe authority", current.calls, decision)
	}
}

func TestCedarNoActivePolicyIsExplicitRollback(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{LastKnownGood: &deployment, State: cedarpolicy.StateNoActivePolicy}}, true)
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want explicit no-policy rollback", current.calls, decision)
	}
}

func TestCedarEnforceUsesAgeValidLastKnownGoodAfterRefreshFailure(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	current := &countingHookPolicy{}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
		Deployment:    &deployment,
		LastKnownGood: &deployment,
		State:         cedarpolicy.StateSuccess,
		Status:        cedarpolicy.CacheStatus{Stale: true},
	}}, true)
	decision, err := provider.DecideHook(context.Background(), risk.HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want age-valid LKG authority", current.calls, decision)
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
