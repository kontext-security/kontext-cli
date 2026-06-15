package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestSaveDecisionRecordsGithubDryRunRows(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()

	event := risk.HookEvent{
		SessionID:     "session-1",
		Agent:         "claude",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git push origin main"},
		ToolUseID:     "toolu_1",
		CWD:           "/tmp/project",
	}
	decision := risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "observed",
		ReasonCode: "deterministic_allow",
		RiskEvent:  risk.RiskEvent{CommandSummary: "git push origin main"},
		GithubPolicy: []githubpolicy.Evaluation{{
			Request:    githubpolicy.Request{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "main"},
			Result:     "deny",
			ReasonCode: githubpolicy.ReasonCodeDeny,
			Reason:     "denied by org-layer deny rule on github.repo.write @ acme/api",
			MatchedRules: []githubpolicy.MatchedRule{
				{ID: "rule-deny", Layer: "org", Effect: "deny", Decided: true},
				{ID: "rule-allow", Layer: "org", Effect: "allow"},
			},
			DecidingRuleID: "rule-deny",
			Mode:           githubpolicy.ModeObserve,
			Epoch:          5,
			Hash:           "hash-5",
		}},
	}
	if _, err := store.SaveDecision(context.Background(), event, decision); err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}

	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{Limit: 10})
	if err != nil {
		t.Fatalf("LedgerBatch() error = %v", err)
	}

	var dryRun LedgerRecord
	decidedRows := 0
	for _, action := range batch.Actions {
		if action["canonical_event_type"] != "request.decided" {
			continue
		}
		decidedRows++
		if action["decision_category"] == "dry_run" {
			dryRun = action
		}
	}
	if decidedRows != 2 {
		t.Fatalf("decided rows = %d, want runtime decision + dry-run decision", decidedRows)
	}
	if dryRun == nil {
		t.Fatal("no dry_run request.decided row found")
	}

	expectations := map[string]any{
		"decision_result": "deny",
		"reason_code":     githubpolicy.ReasonCodeDeny,
		"provider":        "github",
		"resource_class":  "repo",
		"resource_id":     "acme/api",
		"operation":       "github.repo.write",
		"operation_class": "write",
		"policy_id":       "rule-deny",
		"policy_version":  "5",
		"policy_hash":     "hash-5",
		"tool_name":       "Bash",
		"status":          "evaluated",
	}
	for key, want := range expectations {
		if got := dryRun[key]; got != want {
			t.Errorf("dry run %s = %v, want %v", key, got, want)
		}
	}

	matchedRules, ok := dryRun["matched_rules_json"].([]any)
	if !ok || len(matchedRules) != 2 {
		t.Fatalf("matched_rules_json = %v, want two matched rules", dryRun["matched_rules_json"])
	}
	first, _ := matchedRules[0].(map[string]any)
	if first["id"] != "rule-deny" || first["decided"] != true {
		t.Fatalf("matched rule = %v, want deciding rule-deny", first)
	}

	contextJSON, _ := dryRun["context_json"].(map[string]any)
	githubContext, _ := contextJSON["github"].(map[string]any)
	if githubContext["owner"] != "acme" || githubContext["repo"] != "api" || githubContext["branch_or_ref"] != "main" {
		t.Fatalf("context_json.github = %v", githubContext)
	}
	policyContext, _ := contextJSON["github_policy"].(map[string]any)
	if policyContext["mode"] != "observe" || policyContext["hash"] != "hash-5" {
		t.Fatalf("context_json.github_policy = %v", policyContext)
	}
	if policyContext["subjects_resolved"] != false {
		t.Fatalf("subjects_resolved = %v, want false", policyContext["subjects_resolved"])
	}

	identityJSON, _ := dryRun["identity_context_json"].(map[string]any)
	if identityJSON["principal_kind"] != "service_account" {
		t.Fatalf("identity_context_json = %v, want service_account principal", identityJSON)
	}

	if decisionAt, _ := dryRun["decision_at"].(string); decisionAt == "" {
		t.Fatal("dry run decision_at is empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, dryRun["updated_at"].(string)); err != nil {
		t.Fatalf("updated_at = %v: %v", dryRun["updated_at"], err)
	}

	// Every action row appends a chained receipt; dry-run rows must too or
	// the ledger export references break.
	receiptForDryRun := false
	for _, receipt := range batch.Receipts {
		if receipt["action_id"] == dryRun["id"] {
			receiptForDryRun = true
		}
	}
	if !receiptForDryRun {
		t.Fatal("dry run row has no receipt")
	}
}

func TestDryRunRowsDoNotCountAsCriticalActions(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()

	event := risk.HookEvent{
		SessionID:     "session-1",
		Agent:         "claude",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git push origin main"},
		ToolUseID:     "toolu_1",
	}
	decision := risk.RiskDecision{
		Decision: risk.DecisionAllow,
		GithubPolicy: []githubpolicy.Evaluation{{
			Request:    githubpolicy.Request{Action: "github.repo.write", Resource: "acme/api"},
			Result:     "deny",
			ReasonCode: githubpolicy.ReasonCodeDeny,
			Reason:     "would deny",
			Epoch:      5,
			Hash:       "hash-5",
		}},
	}
	if _, err := store.SaveDecision(context.Background(), event, decision); err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}

	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}
	// The runtime decision was allow; the observer-mode would-deny must not
	// surface as a real critical action.
	if summary.Critical != 0 {
		t.Fatalf("Summary.Critical = %d, want 0", summary.Critical)
	}
	if summary.Actions != 1 {
		t.Fatalf("Summary.Actions = %d, want only the runtime decision", summary.Actions)
	}
	events, err := store.Events(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	if len(events) != 1 || events[0].Decision != risk.DecisionAllow {
		t.Fatalf("Events() = %+v, want only the runtime allow decision", events)
	}

	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatalf("Sessions() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0].Critical != 0 {
		t.Fatalf("Sessions() = %+v, want zero critical", sessions)
	}
}

func TestSaveDecisionWithoutGithubPolicyAddsNoExtraRows(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()

	event := risk.HookEvent{
		SessionID:     "session-1",
		Agent:         "claude",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "ls"},
		ToolUseID:     "toolu_1",
	}
	if _, err := store.SaveDecision(context.Background(), event, risk.RiskDecision{Decision: risk.DecisionAllow}); err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}
	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{Limit: 10})
	if err != nil {
		t.Fatalf("LedgerBatch() error = %v", err)
	}
	if len(batch.Actions) != 2 {
		t.Fatalf("actions = %d, want proposed + decided only", len(batch.Actions))
	}
}
