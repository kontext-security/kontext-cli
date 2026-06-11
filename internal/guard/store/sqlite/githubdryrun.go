package sqlite

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

// insertGithubDryRunActions records the synced GitHub policy's would-be
// decisions. Each evaluated action gets its own request.decided row with
// decision_category "dry_run", separate from the runtime's own decided row —
// in observe mode nothing is ever blocked, the dry-run row only documents
// what the policy would have done.
func (s *Store) insertGithubDryRunActions(ctx context.Context, tx *sql.Tx, sessionID string, event risk.HookEvent, decision risk.RiskDecision, now time.Time) error {
	for i, evaluation := range decision.GithubPolicy {
		action, err := githubDryRunActionValues("act_"+uuid.NewString(), sessionID, event, decision, evaluation, now.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			return err
		}
		if err := s.insertActionRecord(ctx, tx, action, "decision", now); err != nil {
			return err
		}
	}
	return nil
}

func githubDryRunActionValues(actionID, sessionID string, event risk.HookEvent, decision risk.RiskDecision, evaluation githubpolicy.Evaluation, now time.Time) (map[string]any, error) {
	riskEvent := decision.RiskEvent
	parametersJSON, parametersHash := mustHashJSON(map[string]any{
		"command_summary": riskEvent.CommandSummary,
		"request_summary": riskEvent.RequestSummary,
		"path_class":      riskEvent.PathClass,
	})
	// The managed endpoint's trusted identity is the service account +
	// installation; hook payloads are session telemetry, not human identity.
	identityJSON, identityHash := mustHashJSON(map[string]any{
		"agent":          event.Agent,
		"principal_kind": "service_account",
	})

	githubContext := map[string]any{}
	if owner, repo, ok := splitRepoSlug(evaluation.Request.Resource); ok {
		githubContext["owner"] = owner
		githubContext["repo"] = repo
	}
	if evaluation.Request.BranchOrRef != "" {
		githubContext["branch_or_ref"] = evaluation.Request.BranchOrRef
	}
	contextPayload := map[string]any{
		"cwd":             event.CWD,
		"hook_event_name": event.HookEventName,
		"github_policy": map[string]any{
			"schema_version":    githubpolicy.SchemaVersion,
			"mode":              evaluation.Mode,
			"epoch":             evaluation.Epoch,
			"hash":              evaluation.Hash,
			"stale":             evaluation.Stale,
			"subjects_resolved": evaluation.SubjectsResolved,
		},
	}
	if len(githubContext) > 0 {
		contextPayload["github"] = githubContext
	}
	contextJSON, contextHash := mustHashJSON(contextPayload)

	matchedRules := evaluation.MatchedRules
	if matchedRules == nil {
		matchedRules = []githubpolicy.MatchedRule{}
	}
	matchedRulesJSON := mustJSONText(matchedRules)

	timestamp := now.Format(time.RFC3339Nano)
	return map[string]any{
		"id":                       actionID,
		"session_id":               sessionID,
		"tool_use_id":              event.ToolUseID,
		"canonical_event_type":     canonicalEventRequestDecided,
		"adapter_event_name":       event.HookEventName,
		"correlation_key":          correlationKey(event),
		"tool_name":                event.ToolName,
		"provider":                 "github",
		"operation":                evaluation.Request.Action,
		"operation_class":          operationClassFromAction(evaluation.Request.Action),
		"resource_class":           "repo",
		"resource_id":              nullIfEmpty(evaluation.Request.Resource),
		"parameters_redacted_json": parametersJSON,
		"parameters_hash":          parametersHash,
		"identity_context_json":    identityJSON,
		"identity_hash":            identityHash,
		"context_json":             contextJSON,
		"context_hash":             contextHash,
		"policy_id":                evaluation.DecidingRuleID,
		"policy_version":           strconv.Itoa(evaluation.Epoch),
		"policy_hash":              evaluation.Hash,
		"default_posture":          "",
		"decision_result":          evaluation.Result,
		"decision_category":        "dry_run",
		"adapter_decision":         "",
		"reason_code":              evaluation.ReasonCode,
		"reason":                   evaluation.Reason,
		"risk_level":               "",
		"risk_score":               nil,
		"risk_threshold":           nil,
		"model_version":            "",
		"confidence":               0.0,
		"matched_rules_json":       matchedRulesJSON,
		"risk_signals_json":        "[]",
		"risk_event_json":          "{}",
		"modifications_json":       "{}",
		"approval_context_json":    "{}",
		"approval_channel":         "",
		"approval_request_id":      "",
		"deferral_context_json":    "{}",
		"status":                   "evaluated",
		"outcome":                  "",
		"output_summary":           "",
		"output_hash":              "",
		"error_redacted":           "",
		"proposed_at":              nil,
		"decision_at":              nullIfEmpty(timestamp),
		"completed_at":             nil,
		"created_at":               timestamp,
		"updated_at":               timestamp,
		"updated_at_cursor_key":    ledgerTimestampCursorKeyFromValues(timestamp),
	}, nil
}

func operationClassFromAction(action string) string {
	if index := strings.LastIndex(action, "."); index >= 0 {
		return action[index+1:]
	}
	return ""
}

func splitRepoSlug(resource string) (owner, repo string, ok bool) {
	owner, repo, found := strings.Cut(resource, "/")
	if !found || owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}
