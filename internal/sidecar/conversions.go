package sidecar

import (
	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func HookResultFromHostedResult(result *backend.ProcessHookEventResult, accessMode backend.HostedAccessMode) hook.Result {
	if result == nil {
		return hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "Kontext access policy could not be evaluated.",
			Mode:     string(accessMode),
		}
	}
	resp := result.Response
	out := hook.Result{
		Reason:     resp.GetReason(),
		ReasonCode: result.ReasonCode,
		RequestID:  result.RequestID,
		Mode:       string(accessMode),
		Epoch:      result.PolicySetEpoch,
	}
	if accessMode != backend.HostedAccessModeEnforce {
		out.Decision = hook.DecisionAllow
		return out
	}
	switch resp.GetDecision() {
	case agentv1.Decision_DECISION_ALLOW:
		out.Decision = hook.DecisionAllow
	case agentv1.Decision_DECISION_DENY:
		fallthrough
	default:
		out.Decision = hook.DecisionDeny
	}
	return out
}
