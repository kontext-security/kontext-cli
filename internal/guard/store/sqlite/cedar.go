package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func (s *Store) insertCedarDecisionAction(ctx context.Context, tx *sql.Tx, sessionID string, event risk.HookEvent, decision risk.RiskDecision, now time.Time) error {
	if decision.Cedar == nil {
		return nil
	}
	action := cedarDecisionActionValues("act_"+uuid.NewString(), sessionID, event, *decision.Cedar, now)
	return s.insertActionRecord(ctx, tx, action, "decision", now)
}

func cedarDecisionActionValues(actionID, sessionID string, event risk.HookEvent, evidence risk.CedarEvidence, now time.Time) map[string]any {
	principal := map[string]any{}
	if evidence.Mapping.EvaluationPrincipal != nil {
		principal["entity_type"] = evidence.Mapping.EvaluationPrincipal.EntityType
		principal["entity_id"] = evidence.Mapping.EvaluationPrincipal.EntityID
	}
	identityJSON, identityHash := mustHashJSON(principal)
	parametersJSON, parametersHash := mustHashJSON(map[string]any{})
	contextJSON, contextHash := mustHashJSON(map[string]any{
		"configured_rollout_mode":  evidence.ConfiguredRolloutMode,
		"applied_rollout_mode":     evidence.AppliedRolloutMode,
		"deployment_identity":      evidence.DeploymentIdentity,
		"response_version":         evidence.ResponseVersion,
		"request_contract_version": evidence.RequestContractVersion,
		"cache_fetched_at":         evidence.CacheFetchedAt,
		"distribution_state":       evidence.DistributionState,
		"cache_stale":              evidence.CacheStale,
		"cache_expired":            evidence.CacheExpired,
		"cache_invalid":            evidence.CacheInvalid,
		"evaluator_version":        evidence.EvaluatorVersion,
		"evaluation_state":         evidence.Mapping.EvaluationState,
		"derived_action":           evidence.Mapping.DerivedCedarAction,
		"evaluation_reason_code":   evidence.Mapping.EvaluationReasonCode,
		"decision_reason_code":     evidence.Mapping.DecisionReasonCode,
		"effective_reason_code":    evidence.Mapping.EffectiveReasonCode,
		"context_diagnostics":      evidence.ContextDiagnostics,
		"engine_error_count":       evidence.EngineErrorCount,
	})

	decisionResult := cedarLedgerDecisionResult(evidence.Mapping.DerivedCedarAction)
	policyID := ""
	if len(evidence.Mapping.DeterminingPolicyIDs) == 1 {
		policyID = evidence.Mapping.DeterminingPolicyIDs[0]
	}
	timestamp := now.Format(time.RFC3339Nano)
	return map[string]any{
		"id": actionID, "session_id": sessionID, "tool_use_id": event.ToolUseID,
		"canonical_event_type": canonicalEventRequestDecided, "adapter_event_name": event.HookEventName,
		"correlation_key": correlationKey(event), "tool_name": event.ToolName,
		"provider": "cedar", "operation": "ToolUse", "operation_class": "tool_use",
		"resource_class": "tool", "resource_id": nullIfEmpty(event.ToolName),
		"parameters_redacted_json": parametersJSON, "parameters_hash": parametersHash,
		"identity_context_json": identityJSON, "identity_hash": identityHash,
		"context_json": contextJSON, "context_hash": contextHash,
		"policy_id": policyID, "policy_version": "", "policy_hash": evidence.PolicyHash,
		"default_posture": "", "decision_result": decisionResult, "decision_category": cedarDecisionCategory(evidence),
		"adapter_decision": "", "reason_code": string(evidence.Mapping.EffectiveReasonCode), "reason": "local Cedar policy evaluation",
		"risk_level": "", "risk_score": nil, "risk_threshold": nil, "model_version": evidence.EvaluatorVersion,
		"confidence": 0.0, "matched_rules_json": mustJSONText(evidence.Mapping.DeterminingPolicyIDs),
		"risk_signals_json": "[]", "risk_event_json": "{}", "modifications_json": "{}",
		"approval_context_json": "{}", "approval_channel": "", "approval_request_id": "", "deferral_context_json": "{}",
		"status": "evaluated", "outcome": "", "output_summary": "", "output_hash": "", "error_redacted": "",
		"tool_input_captured_json": nil, "tool_output_captured_json": nil,
		"proposed_at": nil, "decision_at": timestamp, "completed_at": nil,
		"created_at": timestamp, "updated_at": timestamp, "updated_at_cursor_key": ledgerTimestampCursorKeyFromValues(timestamp),
	}
}

// The dedicated Cedar row preserves evaluator evidence but is never the
// authoritative request decision. SaveDecision's primary request.decided row
// carries the applied outcome (including the cedar_policy decision stage in
// enforce mode), so this auxiliary row must remain excluded from decision
// totals in every rollout mode.
func cedarDecisionCategory(_ risk.CedarEvidence) string {
	return "dry_run"
}

// cedarLedgerDecisionResult projects a Cedar verdict onto the ledger's
// decision_result contract, which the ingest boundary accepts as exactly the
// lowercase set {"allow", "deny"}. An ask verdict has no approval channel in
// v1, so it collapses to a fail-closed "deny" here; the three-valued Cedar
// verdict is preserved verbatim in context_json.derived_action, and the ask
// nature is carried by the reason codes. This mirrors the legacy
// canonicalDecisionResult projection (deny is the default) so Cedar and legacy
// rows share one decision_result vocabulary.
func cedarLedgerDecisionResult(action cedareval.DerivedCedarAction) string {
	if action == cedareval.DerivedCedarActionAllow {
		return string(cedareval.EffectiveExecutionActionAllow)
	}
	return string(cedareval.EffectiveExecutionActionDeny)
}
