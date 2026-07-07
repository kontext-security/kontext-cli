package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func saveCaptureFixtureDecision(t *testing.T, store *Store, hookEvent string, toolInput, toolResponse map[string]any) {
	t.Helper()
	_, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s-capture",
		Agent:         "claude-code",
		HookEventName: hookEvent,
		ToolName:      "Bash",
		ToolUseID:     "tool-capture-1",
		CWD:           "/tmp/project",
		ToolInput:     toolInput,
		ToolResponse:  toolResponse,
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal command",
		ReasonCode: "normal_tool_call",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func capturedColumn(t *testing.T, store *Store, canonicalEvent, column string) sql.NullString {
	t.Helper()
	var value sql.NullString
	err := store.db.QueryRowContext(context.Background(),
		"select "+column+" from authorization_actions where canonical_event_type = ?",
		canonicalEvent,
	).Scan(&value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSaveDecisionCapturesPayloadsInFullMode(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetPayloadCaptureMode(payloadcapture.ModeFull)

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "GITHUB_TOKEN=super-secret-raw-value gh api /user",
	}, nil)
	saveCaptureFixtureDecision(t, store, "PostToolUse", map[string]any{
		"command": "GITHUB_TOKEN=super-secret-raw-value gh api /user",
	}, map[string]any{
		"content": "api_key=another-raw-secret ok",
	})

	// Input is recorded once, on the proposed row only.
	proposedInput := capturedColumn(t, store, "request.proposed", "tool_input_captured_json")
	if !proposedInput.Valid {
		t.Fatal("proposed row is missing the captured tool input")
	}
	var inputRecord map[string]any
	if err := json.Unmarshal([]byte(proposedInput.String), &inputRecord); err != nil {
		t.Fatal(err)
	}
	if inputRecord["mode"] != "full" || inputRecord["redacted"] != true {
		t.Fatalf("unexpected input record: %v", inputRecord)
	}
	if strings.Contains(proposedInput.String, "super-secret-raw-value") {
		t.Fatal("raw secret survived into the stored input record")
	}
	if decidedInput := capturedColumn(t, store, "request.decided", "tool_input_captured_json"); decidedInput.Valid {
		t.Fatal("decision row must not duplicate the captured input")
	}

	// Output is recorded on the observed row.
	observedOutput := capturedColumn(t, store, "request.observed", "tool_output_captured_json")
	if !observedOutput.Valid {
		t.Fatal("observed row is missing the captured tool output")
	}
	if strings.Contains(observedOutput.String, "another-raw-secret") {
		t.Fatal("raw secret survived into the stored output record")
	}
	if observedInput := capturedColumn(t, store, "request.observed", "tool_input_captured_json"); observedInput.Valid {
		t.Fatal("observed row must not carry captured input")
	}
}

func TestSaveDecisionDefaultModeWritesNoCapturedPayloads(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// No SetPayloadCaptureMode call: the default must be byte-identical to
	// the pre-capture behavior.

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "git status",
	}, nil)
	saveCaptureFixtureDecision(t, store, "PostToolUse", map[string]any{
		"command": "git status",
	}, map[string]any{
		"content": "clean working tree",
	})

	for _, canonicalEvent := range []string{"request.proposed", "request.decided", "request.observed"} {
		for _, column := range []string{"tool_input_captured_json", "tool_output_captured_json"} {
			if value := capturedColumn(t, store, canonicalEvent, column); value.Valid {
				t.Fatalf("%s.%s = %q, want NULL in default mode", canonicalEvent, column, value.String)
			}
		}
	}
}

func TestLedgerExportOmitsEmptyCapturedPayloadFields(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "git status",
	}, nil)

	records, err := store.AuthorizationActions(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("expected exported action records")
	}
	for _, record := range records {
		for _, key := range []string{"tool_input_captured_json", "tool_output_captured_json"} {
			if _, present := record[key]; present {
				t.Fatalf("record %v mentions %s; empty captured fields must stay off the wire", record["id"], key)
			}
		}
	}
}

func TestLedgerExportDecodesCapturedPayloadRecords(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetPayloadCaptureMode(payloadcapture.ModeFull)

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "curl https://example.test",
	}, nil)

	records, err := store.AuthorizationActions(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var captured map[string]any
	for _, record := range records {
		if record["canonical_event_type"] != "request.proposed" {
			continue
		}
		decoded, ok := record["tool_input_captured_json"].(map[string]any)
		if !ok {
			t.Fatalf("captured input is %T, want decoded object", record["tool_input_captured_json"])
		}
		captured = decoded
	}
	if captured == nil {
		t.Fatal("no proposed record with captured input exported")
	}
	if captured["mode"] != "full" {
		t.Fatalf("captured mode = %v", captured["mode"])
	}
	if _, hasValue := captured["value"]; !hasValue {
		t.Fatal("captured record is missing its value")
	}
}

func TestMigrationAddsCapturedPayloadColumns(t *testing.T) {
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
  decision_result text,
  status text not null,
  created_at text not null,
  updated_at text not null
);
insert into authorization_actions (
  id, session_id, canonical_event_type, decision_result, status, created_at, updated_at
) values (
  'act_precapture', 's1', 'request.decided', 'allow', 'authorized',
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

	for _, column := range []string{"tool_input_captured_json", "tool_output_captured_json"} {
		var count int
		err := store.db.QueryRowContext(context.Background(), `
select count(*) from pragma_table_info('authorization_actions') where name = ?
		`, column).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("column %s missing after migration", column)
		}
	}

	if value := capturedColumn(t, store, "request.decided", "tool_input_captured_json"); value.Valid {
		t.Fatalf("pre-capture row gained a value: %q", value.String)
	}
}

// capturedRecordJSON falls back to a hardcoded capture_failed literal when
// MarshalJSON fails — a path unreachable for records produced by Capture, so
// it cannot be exercised end-to-end. Pin the literal to the wire format the
// package actually emits so the two cannot drift apart silently.
func TestCaptureFailedFallbackLiteralMatchesWireFormat(t *testing.T) {
	canonical, err := payloadcapture.Payload{
		Mode:   "capture_failed",
		Reason: payloadcapture.ReasonSerializationError,
	}.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal canonical capture_failed record: %v", err)
	}
	const fallback = `{"mode":"capture_failed","reason":"serialization_error"}`
	if string(canonical) != fallback {
		t.Fatalf("fallback literal diverged from wire format:\nliteral: %s\nwire:    %s", fallback, canonical)
	}
}
