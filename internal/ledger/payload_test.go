package ledger

import (
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func TestPayloadJSONShape(t *testing.T) {
	payload := Payload{
		SchemaVersion:  SchemaVersion,
		OrganizationID: "org_123",
		InstallationID: "ins_123",
		BatchID:        "batch_abc",
		SentAt:         "2026-05-31T10:00:00Z",
		Device:         &Device{Label: "test-mac"},
		Sessions:       []sqlite.LedgerRecord{},
		Actions:        []sqlite.LedgerRecord{{"session_id": "claude-session"}},
		Receipts:       []sqlite.LedgerRecord{},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	for _, key := range []string{
		"schema_version",
		"organization_id",
		"installation_id",
		"batch_id",
		"sent_at",
		"agent_sessions",
		"authorization_actions",
		"authorization_receipts",
		"device",
	} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing JSON key %q in %s", key, string(data))
		}
	}
	if _, ok := got["receipt_chain_anchor"]; ok {
		t.Fatalf("receipt_chain_anchor was present for nil anchor: %s", string(data))
	}

	device, ok := got["device"].(map[string]any)
	if !ok {
		t.Fatalf("device = %#v, want object: %s", got["device"], string(data))
	}
	if device["label"] != "test-mac" {
		t.Fatalf("device.label = %#v, want %q", device["label"], "test-mac")
	}
	if _, ok := device["deployment_version"]; ok {
		t.Fatalf("device.deployment_version was present for empty value: %s", string(data))
	}

	for _, key := range []string{"agent_sessions", "authorization_actions", "authorization_receipts"} {
		if _, ok := got[key].([]any); !ok {
			t.Fatalf("%s = %#v, want array: %s", key, got[key], string(data))
		}
	}
}
