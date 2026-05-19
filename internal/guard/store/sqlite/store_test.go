package sqlite

import (
	"context"
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
	if got := countRows(t, store, "authorization_actions"); got != total {
		t.Fatalf("authorization_actions rows = %d, want %d", got, total)
	}
	if got := countRows(t, store, "authorization_receipts"); got != total {
		t.Fatalf("authorization_receipts rows = %d, want %d", got, total)
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
	if decisionResult != "ALLOW" || status != "authorized" || receiptType != "decision" {
		t.Fatalf("ledger row = decision %q status %q receipt %q", decisionResult, status, receiptType)
	}
	if signatureAlgorithm != "none" {
		t.Fatalf("signature algorithm = %q, want none without feature flag", signatureAlgorithm)
	}
}

func TestPostToolUseUpdatesExistingAuthorizationAction(t *testing.T) {
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
	if post.ID != pre.ID {
		t.Fatalf("post ID = %q, want existing action %q", post.ID, pre.ID)
	}

	var eventType, status, outcome, outputHash string
	err = store.db.QueryRowContext(context.Background(), `
select canonical_event_type, status, outcome, output_hash
from authorization_actions
where id = ?
	`, pre.ID).Scan(&eventType, &status, &outcome, &outputHash)
	if err != nil {
		t.Fatal(err)
	}
	if eventType != "action.completed" || status != "completed" || outcome != "success" || outputHash == "" {
		t.Fatalf("action lifecycle = event %q status %q outcome %q output_hash %q", eventType, status, outcome, outputHash)
	}
	if got := countRows(t, store, "authorization_actions"); got != 1 {
		t.Fatalf("authorization_actions rows = %d, want one lifecycle row", got)
	}
	if got := countRows(t, store, "authorization_receipts"); got != 2 {
		t.Fatalf("authorization_receipts rows = %d, want decision and outcome receipts", got)
	}

	var outcomeReason, outcomePayload string
	err = store.db.QueryRowContext(context.Background(), `
select reason_code, receipt_payload_json
from authorization_receipts
where action_id = ? and receipt_type = 'outcome'
	`, pre.ID).Scan(&outcomeReason, &outcomePayload)
	if err != nil {
		t.Fatal(err)
	}
	if outcomeReason != "normal_tool_call" || strings.Contains(outcomePayload, "async_telemetry") {
		t.Fatalf("outcome receipt reason = %q payload = %s, want original authorization evidence", outcomeReason, outcomePayload)
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
	if eventType != "action.proposed" || status != "blocked" || outcome != "not_executed" {
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

func TestUnmatchedPostToolUseWritesDecisionAndOutcomeReceipts(t *testing.T) {
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

	for _, receiptType := range []string{"decision", "outcome"} {
		var count int
		err = store.db.QueryRowContext(context.Background(), `
select count(*)
from authorization_receipts
where action_id = ? and receipt_type = ?
		`, record.ID, receiptType).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s receipts = %d, want 1", receiptType, count)
		}
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
	if len(receipts) != 3 {
		t.Fatalf("receipts = %+v, want 3 receipts", receipts)
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
	if decisionResult != "STEP_UP" || adapterDecision != "unsupported_step_up_fail_closed" || status != "blocked" {
		t.Fatalf("decision_result=%q adapter_decision=%q status=%q", decisionResult, adapterDecision, status)
	}

	events, err := store.Events(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Decision != risk.DecisionDeny {
		t.Fatalf("events = %+v, want unsupported canonical decision projected as deny", events)
	}
}

func TestLedgerBatchExportsSessionsActionsAndReceipts(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

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
	if len(batch.Sessions) != 1 || len(batch.Actions) != 1 || len(batch.Receipts) != 1 {
		t.Fatalf("batch sizes = sessions %d actions %d receipts %d", len(batch.Sessions), len(batch.Actions), len(batch.Receipts))
	}
	if batch.Actions[0]["id"] != record.ID ||
		batch.Actions[0]["decision_result"] != "ALLOW" ||
		batch.Actions[0]["policy_hash"] != "sha256:policy" {
		t.Fatalf("action export = %+v", batch.Actions[0])
	}
	if _, ok := batch.Actions[0]["risk_event_json"].(map[string]any); !ok {
		t.Fatalf("risk_event_json export = %#v, want decoded JSON object", batch.Actions[0]["risk_event_json"])
	}
	if batch.Receipts[0]["action_id"] != record.ID || batch.Receipts[0]["receipt_type"] != "decision" {
		t.Fatalf("receipt export = %+v", batch.Receipts[0])
	}
}

func TestLedgerBatchLimitReturnsReceiptsForSelectedActions(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
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
	if len(batch.Actions) != 1 || batch.Actions[0]["id"] != first.ID {
		t.Fatalf("actions = %+v, want only first action", batch.Actions)
	}
	if len(batch.Receipts) != 2 {
		t.Fatalf("receipts = %+v, want both receipts for selected action", batch.Receipts)
	}
	for _, receipt := range batch.Receipts {
		if receipt["action_id"] != first.ID {
			t.Fatalf("receipt = %+v, want action_id %s", receipt, first.ID)
		}
	}
}

func TestLedgerBatchIncludesReceiptChainAnchorForIncrementalExports(t *testing.T) {
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

	firstUpdated := "2026-05-19T10:00:00Z"
	secondUpdated := "2026-05-19T11:00:00Z"
	if _, err := store.db.ExecContext(context.Background(), `
update authorization_actions
set updated_at = case id
  when ? then ?
  when ? then ?
  else updated_at
end
where id in (?, ?)
	`, first.ID, firstUpdated, second.ID, secondUpdated, first.ID, second.ID); err != nil {
		t.Fatal(err)
	}

	var firstReceiptHash string
	err = store.db.QueryRowContext(context.Background(), `
select receipt_hash
from authorization_receipts
where action_id = ?
	`, first.ID).Scan(&firstReceiptHash)
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
	if len(batch.Actions) != 1 || batch.Actions[0]["id"] != second.ID {
		t.Fatalf("actions = %+v, want only second action", batch.Actions)
	}
	if len(batch.Receipts) != 1 || batch.Receipts[0]["action_id"] != second.ID {
		t.Fatalf("receipts = %+v, want only second action receipt", batch.Receipts)
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
	bridge, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-bridge",
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

	if _, err := store.db.ExecContext(context.Background(), `
update authorization_actions
set updated_at = case id
  when ? then '2026-05-19T11:00:00Z'
  when ? then '2026-05-19T10:00:00Z'
  when ? then '2026-05-19T12:00:00Z'
  else updated_at
end
where id in (?, ?, ?)
	`, first.ID, bridge.ID, second.ID, first.ID, bridge.ID, second.ID); err != nil {
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
	assertRecordIDs(t, batch.Actions, map[string]bool{
		first.ID:  true,
		bridge.ID: true,
		second.ID: true,
	})
	if len(batch.Receipts) != 3 {
		t.Fatalf("receipts = %+v, want contiguous range including bridge receipt", batch.Receipts)
	}
	if batch.Receipts[0]["action_id"] != first.ID ||
		batch.Receipts[1]["action_id"] != bridge.ID ||
		batch.Receipts[2]["action_id"] != second.ID {
		t.Fatalf("receipt range = %+v, want first, bridge, second", batch.Receipts)
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
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  map[string]any{"ok": true},
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
update authorization_receipts
set id = case receipt_type
  when 'decision' then 'rcpt_z'
  when 'outcome' then 'rcpt_a'
  else id
end
where action_id = ?
	`, record.ID); err != nil {
		t.Fatal(err)
	}

	receipts, err := store.AuthorizationReceipts(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatalf("receipts = %+v, want 2", receipts)
	}
	if receipts[0]["receipt_type"] != "decision" || receipts[1]["receipt_type"] != "outcome" {
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
`, "act_bad", "s1", "action.proposed", "ALLOW", "authorized", "normal_tool_call", "normal", `{}`, "2026-05-19T00:00:00Z", "not-a-time"); err != nil {
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
`, "act_bad", "s1", "action.proposed", "ALLOW", "authorized", "normal_tool_call", "normal", `{}`, "2026-05-19T00:00:00Z", "not-a-time"); err != nil {
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
