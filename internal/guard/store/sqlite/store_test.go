package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestEmptyCollectionsEncodeAsJSONArray(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	encodedSessions, err := json.Marshal(sessions)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedSessions) != "[]" {
		t.Fatalf("empty sessions encoded as %s, want []", encodedSessions)
	}

	events, err := store.Events(context.Background(), "missing-session")
	if err != nil {
		t.Fatal(err)
	}
	encodedEvents, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedEvents) != "[]" {
		t.Fatalf("empty events encoded as %s, want []", encodedEvents)
	}
}

func TestMigrationCopiesDecisionNullableFromPartialLegacySchema(t *testing.T) {
	path := t.TempDir() + "/guard.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(context.Background(), `
create table authorization_actions (
  id text primary key,
  session_id text not null,
  canonical_event_type text not null,
  decision_result text not null,
  status text not null,
  created_at text not null,
  updated_at text not null
);
insert into authorization_actions (
  id, session_id, canonical_event_type, decision_result, status, created_at, updated_at
) values (
  'act_legacy', 's1', 'request.decided', 'allow', 'authorized',
  '2026-05-26T10:00:00Z', '2026-05-26T10:00:00Z'
);
`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var notNull int
	err = store.db.QueryRowContext(context.Background(), `
select "notnull"
from pragma_table_info('authorization_actions')
where name = 'decision_result'
	`).Scan(&notNull)
	if err != nil {
		t.Fatal(err)
	}
	if notNull != 0 {
		t.Fatalf("decision_result notnull = %d, want nullable", notNull)
	}

	var decisionResult, resourceID, parametersJSON string
	err = store.db.QueryRowContext(context.Background(), `
select decision_result, coalesce(resource_id, ''), parameters_redacted_json
from authorization_actions
where id = 'act_legacy'
	`).Scan(&decisionResult, &resourceID, &parametersJSON)
	if err != nil {
		t.Fatal(err)
	}
	if decisionResult != "allow" || resourceID != "" || parametersJSON != "{}" {
		t.Fatalf("migrated row decision=%q resource=%q parameters=%q", decisionResult, resourceID, parametersJSON)
	}
}

func TestSaveDecisionGeneratesUniqueIDsConcurrently(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const total = 50
	ids := make(chan string, total)
	errs := make(chan error, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := store.SaveDecision(context.Background(), risk.HookEvent{
				SessionID:     "s1",
				Agent:         "claude-code",
				HookEventName: "PreToolUse",
				ToolName:      "Read",
			}, risk.RiskDecision{
				Decision:   risk.DecisionAllow,
				Reason:     "normal",
				ReasonCode: "normal_tool_call",
				RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
			})
			if err != nil {
				errs <- err
				return
			}
			ids <- record.ID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for id := range ids {
		if !strings.HasPrefix(id, "act_") {
			t.Fatalf("id = %q, want act_ prefix", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id generated: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != total {
		t.Fatalf("saved %d records, want %d", len(seen), total)
	}
	if got := countRows(t, store, "authorization_actions"); got != total*2 {
		t.Fatalf("authorization_actions rows = %d, want %d", got, total*2)
	}
	if got := countRows(t, store, "authorization_receipts"); got != total*2 {
		t.Fatalf("authorization_receipts rows = %d, want %d", got, total*2)
	}
}

func TestSaveDecisionWritesAuthorizationLedger(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	score := 0.72
	threshold := 0.8
	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
		CWD:           "/tmp/project",
	}, risk.RiskDecision{
		Decision:     risk.DecisionAllow,
		Reason:       "normal command",
		ReasonCode:   "normal_tool_call",
		RiskScore:    &score,
		Threshold:    &threshold,
		ModelVersion: "model-v1",
		RiskEvent: risk.RiskEvent{
			Type:           risk.EventNormalToolCall,
			Operation:      "run_tests",
			OperationClass: "read",
			ResourceClass:  "repo",
			Signals:        []string{"local_test"},
			PolicyVersion:  "guard-policy-v1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record.ID, "act_") {
		t.Fatalf("record ID = %q, want action ID", record.ID)
	}

	var decisionResult, status, receiptType, signatureAlgorithm string
	err = store.db.QueryRowContext(context.Background(), `
select a.decision_result, a.status, r.receipt_type, r.signature_algorithm
from authorization_actions a
join authorization_receipts r on r.action_id = a.id
where a.id = ?
	`, record.ID).Scan(&decisionResult, &status, &receiptType, &signatureAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	if decisionResult != "allow" || status != "authorized" || receiptType != "decision" {
		t.Fatalf("ledger row = decision %q status %q receipt %q", decisionResult, status, receiptType)
	}
	if signatureAlgorithm != "none" {
		t.Fatalf("signature algorithm = %q, want none without feature flag", signatureAlgorithm)
	}
}

func TestSaveDecisionEnrichesGitHubRepoResource(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	event := risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
		ToolInput:     map[string]any{"command": "gh repo view kontext-security/kontext-cli"},
	}
	decision, err := risk.DecideRisk(event)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.SaveDecision(context.Background(), event, decision)
	if err != nil {
		t.Fatal(err)
	}

	var provider, operation, operationClass, resourceClass, resourceID, riskJSON string
	err = store.db.QueryRowContext(context.Background(), `
select provider, operation, operation_class, resource_class, resource_id, risk_event_json
from authorization_actions
where id = ?
	`, record.ID).Scan(&provider, &operation, &operationClass, &resourceClass, &resourceID, &riskJSON)
	if err != nil {
		t.Fatal(err)
	}
	if provider != "github" || operation != "gh repo view" || operationClass != "read" || resourceClass != "repo" || resourceID != "kontext-security/kontext-cli" {
		t.Fatalf("github action = provider %q operation %q/%q resource %q/%q", provider, operation, operationClass, resourceClass, resourceID)
	}
	var riskEvent risk.RiskEvent
	if err := json.Unmarshal([]byte(riskJSON), &riskEvent); err != nil {
		t.Fatal(err)
	}
	if riskEvent.Provider != "github" || riskEvent.ResourceClass != "repo" || riskEvent.Environment != "local" {
		t.Fatalf("risk event = %+v, want github repo local", riskEvent)
	}
}

func TestGitHubRepoFromCommandPrefersGitHubURLRepository(t *testing.T) {
	got := githubRepoFromCommand("git clone https://github.com/kontext-security/kontext-cli.git")
	if got != "kontext-security/kontext-cli" {
		t.Fatalf("repo = %q, want kontext-security/kontext-cli", got)
	}

	got = githubRepoFromCommand("gh pr view https://github.com/kontext-security/kontext-cli/pull/223")
	if got != "kontext-security/kontext-cli" {
		t.Fatalf("pull URL repo = %q, want kontext-security/kontext-cli", got)
	}
}

func TestPostToolUseWritesObservationAction(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	pre, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall, CommandSummary: "go test ./..."},
	})
	if err != nil {
		t.Fatal(err)
	}

	post, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
		ToolResponse:  map[string]any{"ok": true},
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall, CommandSummary: "go test ./..."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if post.ID == pre.ID {
		t.Fatalf("post ID = %q, want separate observation action", post.ID)
	}

	var eventType, status, outcome, outputHash string
	err = store.db.QueryRowContext(context.Background(), `
	select canonical_event_type, status, outcome, output_hash
	from authorization_actions
	where id = ?
		`, post.ID).Scan(&eventType, &status, &outcome, &outputHash)
	if err != nil {
		t.Fatal(err)
	}
	if eventType != "request.observed" || status != "completed" || outcome != "success" || outputHash == "" {
		t.Fatalf("action lifecycle = event %q status %q outcome %q output_hash %q", eventType, status, outcome, outputHash)
	}
	if got := countRows(t, store, "authorization_actions"); got != 3 {
		t.Fatalf("authorization_actions rows = %d, want proposed, decided, and observed rows", got)
	}
	if got := countRows(t, store, "authorization_receipts"); got != 3 {
		t.Fatalf("authorization_receipts rows = %d, want event, decision, and outcome receipts", got)
	}

	var outcomeReason, outcomePayload string
	err = store.db.QueryRowContext(context.Background(), `
select reason_code, receipt_payload_json
	from authorization_receipts
	where action_id = ? and receipt_type = 'outcome'
		`, post.ID).Scan(&outcomeReason, &outcomePayload)
	if err != nil {
		t.Fatal(err)
	}
	if outcomeReason != "" || strings.Contains(outcomePayload, "async_telemetry") {
		t.Fatalf("outcome receipt reason = %q payload = %s, want observation evidence without fake decision", outcomeReason, outcomePayload)
	}
}

func TestSessionLifecycleHooksUseCanonicalSessionEvents(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, hookEvent := range []string{"SessionStart", "SessionEnd"} {
		if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
			SessionID:     "s1",
			Agent:         "claude-code",
			HookEventName: hookEvent,
			CWD:           "/tmp/project",
		}, risk.RiskDecision{
			Decision:   risk.DecisionAllow,
			Reason:     "async telemetry event recorded",
			ReasonCode: "async_telemetry",
			RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
		}); err != nil {
			t.Fatalf("SaveDecision(%s) error = %v", hookEvent, err)
		}
	}

	rows, err := store.db.QueryContext(context.Background(), `
select canonical_event_type, status, outcome, proposed_at is not null, completed_at is not null
from authorization_actions
where adapter_event_name in ('SessionStart', 'SessionEnd')
order by created_at
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type lifecycleRow struct {
		eventType    string
		status       string
		outcome      string
		hasProposed  bool
		hasCompleted bool
	}
	var got []lifecycleRow
	for rows.Next() {
		var row lifecycleRow
		if err := rows.Scan(&row.eventType, &row.status, &row.outcome, &row.hasProposed, &row.hasCompleted); err != nil {
			t.Fatal(err)
		}
		got = append(got, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []lifecycleRow{
		{eventType: "session.start", status: "started", outcome: "not_executed", hasProposed: true},
		{eventType: "session.end", status: "completed", outcome: "not_executed", hasCompleted: true},
	}
	if len(got) != len(want) {
		t.Fatalf("lifecycle rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lifecycle row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestPostToolUseDoesNotCompleteBlockedAuthorizationAction(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	pre, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionDeny,
		Reason:     "blocked",
		ReasonCode: "credential_access",
		RiskEvent:  risk.RiskEvent{Type: risk.EventCredentialAccess, CommandSummary: "cat .env"},
	})
	if err != nil {
		t.Fatal(err)
	}

	post, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
		ToolResponse:  map[string]any{"ok": true},
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall, CommandSummary: "cat .env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if post.ID == pre.ID {
		t.Fatalf("post ID = %q, want separate telemetry action for blocked pre-hook action", post.ID)
	}

	var eventType, status, outcome string
	err = store.db.QueryRowContext(context.Background(), `
select canonical_event_type, status, outcome
from authorization_actions
where id = ?
	`, pre.ID).Scan(&eventType, &status, &outcome)
	if err != nil {
		t.Fatal(err)
	}
	if eventType != "request.decided" || status != "blocked" || outcome != "not_executed" {
		t.Fatalf("blocked action lifecycle = event %q status %q outcome %q", eventType, status, outcome)
	}

	var blockedReceipts int
	err = store.db.QueryRowContext(context.Background(), `
select count(*)
from authorization_receipts
where action_id = ?
	`, pre.ID).Scan(&blockedReceipts)
	if err != nil {
		t.Fatal(err)
	}
	if blockedReceipts != 1 {
		t.Fatalf("blocked action receipts = %d, want only decision receipt", blockedReceipts)
	}
}

func TestUnmatchedPostToolUseWritesOutcomeReceipt(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  map[string]any{"ok": true},
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall, CommandSummary: "go test ./..."},
	})
	if err != nil {
		t.Fatal(err)
	}

	var status, outcome string
	err = store.db.QueryRowContext(context.Background(), `
select status, outcome
from authorization_actions
where id = ?
	`, record.ID).Scan(&status, &outcome)
	if err != nil {
		t.Fatal(err)
	}
	if status != "completed" || outcome != "success" {
		t.Fatalf("standalone post action status = %q outcome = %q", status, outcome)
	}

	var count int
	err = store.db.QueryRowContext(context.Background(), `
	select count(*)
	from authorization_receipts
	where action_id = ? and receipt_type = ?
		`, record.ID, "outcome").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("outcome receipts = %d, want 1", count)
	}
}

func TestLedgerSigningFeatureFlagSignsReceipts(t *testing.T) {
	t.Setenv(ledgerSigningEnv, "1")
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
	}, risk.RiskDecision{
		Decision:   risk.DecisionDeny,
		Reason:     "blocked",
		ReasonCode: "blocked",
		RiskEvent:  risk.RiskEvent{Type: risk.EventCredentialAccess},
	})
	if err != nil {
		t.Fatal(err)
	}

	var signature, algorithm, keyID string
	err = store.db.QueryRowContext(context.Background(), `
select signature, signature_algorithm, key_id
from authorization_receipts
where action_id = ?
	`, record.ID).Scan(&signature, &algorithm, &keyID)
	if err != nil {
		t.Fatal(err)
	}
	if signature == "" || algorithm != "ed25519" || !strings.HasPrefix(keyID, "local-ed25519:") {
		t.Fatalf("signature = %q algorithm = %q keyID = %q", signature, algorithm, keyID)
	}
	if err := store.VerifyReceipts(context.Background()); err != nil {
		t.Fatalf("VerifyReceipts() error = %v", err)
	}

	if _, err := store.db.ExecContext(context.Background(), `
update authorization_receipts
set signature = '', signature_algorithm = 'none', key_id = ''
where action_id = ?
	`, record.ID); err != nil {
		t.Fatal(err)
	}
	err = store.VerifyReceipts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "missing an ed25519 signature") {
		t.Fatalf("VerifyReceipts() error = %v, want missing signature error", err)
	}
}

func TestVerifyReceiptsChecksSignedPayloadPreviousHash(t *testing.T) {
	t.Setenv(ledgerSigningEnv, "1")
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, toolUseID := range []string{"tool-1", "tool-2", "tool-3"} {
		if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
			SessionID:     "s1",
			HookEventName: "PreToolUse",
			ToolName:      "Read",
			ToolUseID:     toolUseID,
		}, risk.RiskDecision{
			Decision:   risk.DecisionAllow,
			Reason:     "normal",
			ReasonCode: "normal_tool_call",
			RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.VerifyReceipts(context.Background()); err != nil {
		t.Fatalf("VerifyReceipts() initial error = %v", err)
	}

	rows, err := store.db.QueryContext(context.Background(), `
select id, receipt_hash
from authorization_receipts
order by rowid
	`)
	if err != nil {
		t.Fatal(err)
	}
	type receiptRow struct {
		id   string
		hash string
	}
	receipts := []receiptRow{}
	for rows.Next() {
		var item receiptRow
		if err := rows.Scan(&item.id, &item.hash); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		receipts = append(receipts, item)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 6 {
		t.Fatalf("receipts = %+v, want 6 receipts", receipts)
	}

	if _, err := store.db.ExecContext(context.Background(), `
delete from authorization_receipts
where id = ?
	`, receipts[1].id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
update authorization_receipts
set previous_receipt_hash = ?
where id = ?
	`, receipts[0].hash, receipts[2].id); err != nil {
		t.Fatal(err)
	}

	err = store.VerifyReceipts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "payload previous hash mismatch") {
		t.Fatalf("VerifyReceipts() error = %v, want payload previous hash mismatch", err)
	}
}

func TestUnsupportedCanonicalDecisionFailsClosedInLedger(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
	}, risk.RiskDecision{
		Decision:   risk.Decision("step_up"),
		Reason:     "approval required",
		ReasonCode: "approval_required",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decisionResult, adapterDecision, status string
	err = store.db.QueryRowContext(context.Background(), `
select decision_result, adapter_decision, status
from authorization_actions
where id = ?
	`, record.ID).Scan(&decisionResult, &adapterDecision, &status)
	if err != nil {
		t.Fatal(err)
	}
	if decisionResult != "ask" || adapterDecision != "step_up" || status != "needs_approval" {
		t.Fatalf("decision_result=%q adapter_decision=%q status=%q", decisionResult, adapterDecision, status)
	}

	events, err := store.Events(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Decision != risk.Decision("ask") {
		t.Fatalf("events = %+v, want step-up projected as ask", events)
	}

	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Critical != 1 || summary.Actions != 1 {
		t.Fatalf("summary = %+v, want ask counted as one critical action", summary)
	}
	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Critical != 1 || sessions[0].Actions != 1 {
		t.Fatalf("sessions = %+v, want ask counted as one critical action", sessions)
	}
	sessionSummary, err := store.SessionSummary(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if sessionSummary.Critical != 1 || sessionSummary.Actions != 1 {
		t.Fatalf("session summary = %+v, want ask counted as one critical action", sessionSummary)
	}
}

func TestLedgerBatchExportsSessionsActionsAndReceipts(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.EnsureObservedSessionWithMode(context.Background(), "s1", "claude-code", "/tmp/project", "observe"); err != nil {
		t.Fatal(err)
	}
	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		Agent:         "claude-code",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent: risk.RiskEvent{
			Type:          risk.EventNormalToolCall,
			PolicyVersion: "guard-policy-v1",
			PolicyHash:    "sha256:policy",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Sessions) != 1 || len(batch.Actions) != 2 || len(batch.Receipts) != 2 {
		t.Fatalf("batch sizes = sessions %d actions %d receipts %d", len(batch.Sessions), len(batch.Actions), len(batch.Receipts))
	}
	if batch.Sessions[0]["mode"] != "observe" {
		t.Fatalf("session export mode = %q, want observe", batch.Sessions[0]["mode"])
	}
	decided := ledgerRecordByID(batch.Actions, record.ID)
	if decided == nil ||
		decided["canonical_event_type"] != "request.decided" ||
		decided["decision_result"] != "allow" ||
		decided["policy_hash"] != "sha256:policy" {
		t.Fatalf("decided action export = %+v", decided)
	}
	if _, ok := decided["risk_event_json"].(map[string]any); !ok {
		t.Fatalf("risk_event_json export = %#v, want decoded JSON object", decided["risk_event_json"])
	}
	receipt := ledgerRecordByField(batch.Receipts, "action_id", record.ID)
	if receipt == nil || receipt["receipt_type"] != "decision" {
		t.Fatalf("receipt export = %+v", receipt)
	}
}

func TestLedgerBatchLimitReturnsReceiptsForSelectedActions(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolUseID:     "tool-1",
		ToolResponse:  map[string]any{"ok": true},
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-2",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}

	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Actions) != 1 || batch.Actions[0]["canonical_event_type"] != "request.proposed" {
		t.Fatalf("actions = %+v, want only first proposed action", batch.Actions)
	}
	if len(batch.Receipts) != 1 {
		t.Fatalf("receipts = %+v, want receipt for selected action", batch.Receipts)
	}
	selectedID, _ := batch.Actions[0]["id"].(string)
	for _, receipt := range batch.Receipts {
		if receipt["action_id"] != selectedID {
			t.Fatalf("receipt = %+v, want action_id %s", receipt, selectedID)
		}
	}
}

func TestLedgerBatchCursorUsesUpdatedAtAndActionID(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-2",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	})
	if err != nil {
		t.Fatal(err)
	}

	sharedUpdated := "2026-05-19T10:00:00Z"
	if _, err := store.db.ExecContext(context.Background(), `
update authorization_actions
set updated_at = ?
where id in (?, ?)
	`, sharedUpdated, first.ID, second.ID); err != nil {
		t.Fatal(err)
	}

	firstBatch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if firstBatch.Cursor == nil {
		t.Fatal("first batch cursor = nil")
	}

	secondBatch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{
		UpdatedAfter:   &firstBatch.Cursor.UpdatedAt,
		UpdatedAfterID: firstBatch.Cursor.ActionID,
		Limit:          1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secondBatch.Actions) != 1 || secondBatch.Actions[0]["id"] == firstBatch.Cursor.ActionID {
		t.Fatalf("second batch actions = %+v, cursor = %+v", secondBatch.Actions, firstBatch.Cursor)
	}
}

func TestLedgerBatchIncludesReceiptChainAnchorForIncrementalExports(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-2",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}

	firstUpdated := "2026-05-19T10:00:00Z"
	secondUpdated := "2026-05-19T11:00:00Z"
	if _, err := store.db.ExecContext(context.Background(), `
	update authorization_actions
	set updated_at = case tool_use_id
	  when ? then ?
	  when ? then ?
	  else updated_at
	end
	where session_id = ? and tool_use_id in (?, ?)
		`, "tool-1", firstUpdated, "tool-2", secondUpdated, "s1", "tool-1", "tool-2"); err != nil {
		t.Fatal(err)
	}

	var firstReceiptHash string
	err = store.db.QueryRowContext(context.Background(), `
	select receipt_hash
	from authorization_receipts
	where action_id in (select id from authorization_actions where session_id = ? and tool_use_id = ?)
	order by rowid desc
	limit 1
		`, "s1", "tool-1").Scan(&firstReceiptHash)
	if err != nil {
		t.Fatal(err)
	}

	cursor, err := time.Parse(time.RFC3339Nano, "2026-05-19T10:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{UpdatedAfter: &cursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Actions) != 2 {
		t.Fatalf("actions = %+v, want second proposed and decided actions", batch.Actions)
	}
	if len(batch.Receipts) != 2 {
		t.Fatalf("receipts = %+v, want second proposed and decided receipts", batch.Receipts)
	}
	if batch.ReceiptChainAnchor == nil || batch.ReceiptChainAnchor.PreviousReceiptHash != firstReceiptHash {
		t.Fatalf("receipt chain anchor = %+v, want previous hash %q", batch.ReceiptChainAnchor, firstReceiptHash)
	}
	if batch.Receipts[0]["previous_receipt_hash"] != firstReceiptHash {
		t.Fatalf("first receipt previous hash = %q, want %q", batch.Receipts[0]["previous_receipt_hash"], firstReceiptHash)
	}
}

func TestLedgerBatchIncludesContiguousReceiptRangeAndBridgeActions(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-bridge",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-2",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(context.Background(), `
	update authorization_actions
	set updated_at = case tool_use_id
	  when ? then '2026-05-19T11:00:00Z'
	  when ? then '2026-05-19T10:00:00Z'
	  when ? then '2026-05-19T12:00:00Z'
	  else updated_at
	end
	where session_id = ? and tool_use_id in (?, ?, ?)
		`, "tool-1", "tool-bridge", "tool-2", "s1", "tool-1", "tool-bridge", "tool-2"); err != nil {
		t.Fatal(err)
	}

	cursor, err := time.Parse(time.RFC3339Nano, "2026-05-19T10:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{UpdatedAfter: &cursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Actions) != 6 {
		t.Fatalf("actions = %+v, want selected actions plus bridge actions", batch.Actions)
	}
	if len(batch.Receipts) != 6 {
		t.Fatalf("receipts = %+v, want contiguous range including bridge receipt", batch.Receipts)
	}
	if receiptCountForTool(t, store, batch.Receipts, "tool-bridge") != 2 {
		t.Fatalf("receipt range = %+v, want bridge receipts included", batch.Receipts)
	}
}

func TestAuthorizationReceiptsExportUsesChainOrder(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
	update authorization_receipts
	set id = case receipt_type
	  when 'event' then 'rcpt_z'
	  when 'decision' then 'rcpt_a'
	  else id
	end
	where session_id = ?
		`, record.SessionID); err != nil {
		t.Fatal(err)
	}

	receipts, err := store.AuthorizationReceipts(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatalf("receipts = %+v, want 2", receipts)
	}
	if receipts[0]["receipt_type"] != "event" || receipts[1]["receipt_type"] != "decision" {
		t.Fatalf("receipt export order = %+v, want chain insertion order", receipts)
	}
}

func TestVerifyReceiptsDetectsTampering(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	record, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyReceipts(context.Background()); err != nil {
		t.Fatalf("VerifyReceipts() initial error = %v", err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
update authorization_receipts
set receipt_payload_json = ?
where action_id = ?
	`, `{"tampered":true}`, record.ID); err != nil {
		t.Fatal(err)
	}
	err = store.VerifyReceipts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("VerifyReceipts() error = %v, want hash mismatch", err)
	}
}

func TestOpenAndCloseSessionRecordsLifecycle(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	opened, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123")
	if err != nil {
		t.Fatal(err)
	}
	if opened.ID != "session-123" ||
		opened.Agent != "claude" ||
		opened.CWD != "/tmp/project" ||
		opened.Source != "wrapper_owned" ||
		opened.Status != "open" ||
		opened.ExternalID != "backend-123" ||
		opened.ClosedAt != nil {
		t.Fatalf("opened session = %+v", opened)
	}

	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}
	closed, err := store.Session(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "closed" || closed.ClosedAt == nil {
		t.Fatalf("closed session = %+v, want closed with closed_at", closed)
	}
}

func TestCloseSessionNormalizesEmptySessionID(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "", "claude", "/tmp/project", "daemon_observed", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	closed, err := store.Session(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "closed" || closed.ClosedAt == nil {
		t.Fatalf("closed session = %+v, want normalized local session closed", closed)
	}
}

func TestOpenSessionDoesNotDowngradeWrapperOwnedSource(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.OpenSession(context.Background(), "session-123", "", "", "daemon_observed", "")
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Source != "wrapper_owned" || reopened.ExternalID != "backend-123" {
		t.Fatalf("reopened session = %+v, want wrapper-owned source preserved", reopened)
	}
}

func TestEnsureObservedSessionPreservesExistingLifecycle(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}

	observed, err := store.EnsureObservedSession(context.Background(), "session-123", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Source != "wrapper_owned" ||
		observed.Status != "closed" ||
		observed.ExternalID != "backend-123" ||
		observed.ClosedAt == nil {
		t.Fatalf("observed session = %+v, want existing wrapper-owned closed session", observed)
	}
}

func TestEnsureObservedSessionReopensClosedDaemonObservedSession(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "daemon_observed", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}

	observed, err := store.EnsureObservedSession(context.Background(), "session-123", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Source != "daemon_observed" || observed.Status != "open" || observed.ClosedAt != nil {
		t.Fatalf("observed session = %+v, want reopened daemon-observed session", observed)
	}
}

func TestCloseStaleDaemonObservedSessionsOnlyClosesDaemonObserved(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "daemon-old", "claude", "/tmp/project", "daemon_observed", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenSession(context.Background(), "wrapper-old", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(context.Background(), `
update agent_sessions set updated_at = ? where id in ('daemon-old', 'wrapper-old')
	`, old); err != nil {
		t.Fatal(err)
	}

	if err := store.CloseStaleDaemonObservedSessions(context.Background(), time.Now().UTC().Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	daemon, err := store.Session(context.Background(), "daemon-old")
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := store.Session(context.Background(), "wrapper-old")
	if err != nil {
		t.Fatal(err)
	}
	if daemon.Status != "closed" || daemon.ClosedAt == nil {
		t.Fatalf("daemon session = %+v, want closed", daemon)
	}
	if wrapper.Status != "open" || wrapper.ClosedAt != nil {
		t.Fatalf("wrapper session = %+v, want still open", wrapper)
	}
}

func TestSessionsRejectsInvalidStoredTimestamp(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.ExecContext(context.Background(), `
insert into authorization_actions(
  id, session_id, canonical_event_type, decision_result, status, reason_code, reason, risk_event_json, created_at, updated_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "act_bad", "s1", "request.decided", "allow", "authorized", "normal_tool_call", "normal", `{}`, "2026-05-19T00:00:00Z", "not-a-time"); err != nil {
		t.Fatal(err)
	}

	_, err = store.Sessions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parse session latest_at") {
		t.Fatalf("err = %v, want invalid latest_at parse error", err)
	}
}

func TestEventsRejectsInvalidStoredTimestamp(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.ExecContext(context.Background(), `
insert into authorization_actions(
  id, session_id, canonical_event_type, decision_result, status, reason_code, reason, risk_event_json, created_at, updated_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "act_bad", "s1", "request.decided", "allow", "authorized", "normal_tool_call", "normal", `{}`, "2026-05-19T00:00:00Z", "not-a-time"); err != nil {
		t.Fatal(err)
	}

	_, err = store.Events(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "parse decision created_at") {
		t.Fatalf("err = %v, want invalid created_at parse error", err)
	}
}

func countRows(t *testing.T, store *Store, table string) int {
	t.Helper()
	var count int
	if err := store.db.QueryRowContext(context.Background(), "select count(*) from "+table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func ledgerRecordByID(records []LedgerRecord, id string) LedgerRecord {
	return ledgerRecordByField(records, "id", id)
}

func ledgerRecordByField(records []LedgerRecord, field, value string) LedgerRecord {
	for _, record := range records {
		if record[field] == value {
			return record
		}
	}
	return nil
}

func receiptCountForTool(t *testing.T, store *Store, receipts []LedgerRecord, toolUseID string) int {
	t.Helper()
	count := 0
	for _, receipt := range receipts {
		actionID, _ := receipt["action_id"].(string)
		var storedToolUseID string
		if err := store.db.QueryRowContext(context.Background(), `
	select coalesce(tool_use_id, '')
	from authorization_actions
	where id = ?
		`, actionID).Scan(&storedToolUseID); err != nil {
			t.Fatal(err)
		}
		if storedToolUseID == toolUseID {
			count++
		}
	}
	return count
}

func assertRecordIDs(t *testing.T, records []LedgerRecord, want map[string]bool) {
	t.Helper()
	got := map[string]bool{}
	for _, record := range records {
		id, ok := record["id"].(string)
		if !ok || id == "" {
			t.Fatalf("record missing id: %+v", record)
		}
		got[id] = true
	}
	if len(got) != len(want) {
		t.Fatalf("record IDs = %+v, want %+v", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("record IDs = %+v, missing %s", got, id)
		}
	}
}
