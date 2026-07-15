package server

import (
	"context"
	"errors"
	"sync"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

const cedarEvaluatorVersion = "cedar-go/v1.8.0"

type cedarPolicyProvider struct {
	current   PolicyProvider
	snapshots cedarpolicy.SnapshotProvider

	mu        sync.Mutex
	identity  string
	evaluator *cedareval.Evaluator
	parseErr  error
}

func newCedarPolicyProvider(current PolicyProvider, snapshots cedarpolicy.SnapshotProvider) PolicyProvider {
	if snapshots == nil {
		return current
	}
	return &cedarPolicyProvider{current: current, snapshots: snapshots}
}

func (p *cedarPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	decision, err := p.current.DecideHook(ctx, event)
	if err != nil || event.HookEventName != hook.HookPreToolUse.String() {
		return decision, err
	}

	snapshot := p.snapshots.Current()
	evidence := p.evaluate(snapshot, event, executionAction(decision.Decision))
	decision.Cedar = &evidence
	return decision, nil
}

func (p *cedarPolicyProvider) evaluate(snapshot cedarpolicy.Snapshot, event risk.HookEvent, current cedareval.EffectiveExecutionAction) risk.CedarEvidence {
	evidence := risk.CedarEvidence{
		AppliedRolloutMode: cedareval.RolloutModeObserve,
		CacheFetchedAt:     snapshot.Status.FetchedAt,
		CacheStale:         snapshot.Status.Stale,
		EvaluatorVersion:   cedarEvaluatorVersion,
		ContextDiagnostics: []cedareval.ContextDiagnostic{},
	}
	outcome := cedareval.EvaluationOutcome{State: cedareval.EvaluationStateFailed, Reason: cedareval.ReasonPolicyMissing}
	var principal *cedareval.EvaluationPrincipal

	if deployment := snapshot.Deployment; deployment != nil {
		evidence.ResponseVersion = deployment.ResponseVersion
		evidence.RequestContractVersion = deployment.RequestContractVersion
		evidence.PolicyHash = deployment.PolicyHash
		evidence.DeploymentIdentity = deployment.DeploymentIdentity
		evidence.ConfiguredRolloutMode = deployment.RolloutMode
		principalValue := deployment.EvaluationPrincipal
		principal = &principalValue

		evaluator, parseErr := p.evaluatorFor(deployment)
		if parseErr != nil {
			outcome.Reason = cedareval.ReasonInvalidCachedPolicy
			evidence.EngineErrorCount = 1
		} else {
			input, inputErr := cedareval.InputFromEvent(principalValue, hookEvent(event))
			if inputErr != nil {
				outcome.Reason = cedareval.ReasonRequestConversionFailed
			} else if result, evaluateErr := evaluator.Evaluate(input); evaluateErr != nil {
				var conversionErr *cedareval.ConversionError
				if errors.As(evaluateErr, &conversionErr) {
					outcome.Reason = cedareval.ReasonRequestConversionFailed
				} else {
					outcome.Reason = cedareval.ReasonEngineError
				}
				evidence.EngineErrorCount = 1
			} else {
				outcome = cedareval.EvaluationOutcome{
					State:                cedareval.EvaluationStateEvaluated,
					Decision:             result.Decision,
					Ask:                  result.Ask,
					DeterminingPolicyIDs: result.DeterminingPolicyIDs,
				}
				evidence.ContextDiagnostics = result.ContextDiagnostics
				evidence.EngineErrorCount = len(result.EngineDiagnostics.Errors)
			}
		}
	} else if isPrincipalState(snapshot.State) {
		outcome = cedareval.EvaluationOutcome{State: cedareval.EvaluationStatePrincipalUnresolved, Reason: cedareval.ReasonPrincipalUnresolved}
	} else if snapshot.Status.Stale {
		outcome.Reason = cedareval.ReasonStaleCachedPolicy
	}

	evidence.AppliedRolloutMode = cedareval.RolloutModeObserve
	mapping, err := cedareval.MapDecision(cedareval.DecisionMappingInput{
		RolloutMode:            cedareval.RolloutModeObserve,
		CurrentAuthorityAction: current,
		EvaluationPrincipal:    principal,
		Evaluation:             outcome,
	})
	if err != nil {
		fallback, _ := cedareval.MapDecision(cedareval.DecisionMappingInput{
			RolloutMode:            cedareval.RolloutModeObserve,
			CurrentAuthorityAction: current,
			Evaluation:             cedareval.EvaluationOutcome{State: cedareval.EvaluationStateFailed, Reason: cedareval.ReasonEngineError},
		})
		evidence.Mapping = fallback
		evidence.AppliedRolloutMode = cedareval.RolloutModeObserve
		evidence.EngineErrorCount++
		return evidence
	}
	evidence.Mapping = mapping
	return evidence
}

func (p *cedarPolicyProvider) evaluatorFor(deployment *cedarpolicy.Deployment) (*cedareval.Evaluator, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.identity != deployment.DeploymentIdentity {
		p.identity = deployment.DeploymentIdentity
		p.evaluator, p.parseErr = cedareval.New(deployment.PolicyText)
	}
	return p.evaluator, p.parseErr
}

func executionAction(decision risk.Decision) cedareval.EffectiveExecutionAction {
	if decision == risk.DecisionDeny {
		return cedareval.EffectiveExecutionActionDeny
	}
	return cedareval.EffectiveExecutionActionAllow
}

func hookEvent(event risk.HookEvent) hook.Event {
	return hook.Event{SessionID: event.SessionID, Agent: event.Agent, HookName: hook.HookName(event.HookEventName), ToolName: event.ToolName, ToolInput: event.ToolInput, ToolResponse: event.ToolResponse, ToolUseID: event.ToolUseID, CWD: event.CWD}
}

func isPrincipalState(state cedarpolicy.State) bool {
	switch state {
	case cedarpolicy.StatePrincipalUnavailable:
		return true
	default:
		return false
	}
}
