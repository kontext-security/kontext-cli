package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/ledger"
)

func TestFlushPostsLedgerBatchWithInstallationIdentity(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got ledger.Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		DeviceLabel:    "michel-macbook",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.SchemaVersion != ledger.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, ledger.SchemaVersion)
	}
	if got.OrganizationID != "org_123" {
		t.Fatalf("organization_id = %q", got.OrganizationID)
	}
	if got.InstallationID != "ins_0123456789abcdefghijklmnopqrstuv" {
		t.Fatalf("installation_id = %q", got.InstallationID)
	}
	if got.Device == nil || got.Device.Label != "michel-macbook" {
		t.Fatalf("device = %+v", got.Device)
	}
	if len(got.Sessions) != 1 || len(got.Actions) != 2 || len(got.Receipts) != 2 {
		t.Fatalf("batch counts = sessions %d actions %d receipts %d", len(got.Sessions), len(got.Actions), len(got.Receipts))
	}
	if got.Actions[0]["canonical_event_type"] != "request.proposed" ||
		got.Actions[1]["canonical_event_type"] != "request.decided" ||
		got.Actions[1]["decision_result"] != "allow" {
		t.Fatalf("actions = %+v, want proposed and decided ledger events", got.Actions)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil {
		t.Fatal("updated_after was not persisted")
	}
}

func TestFlushOmitsBlankDeviceLabel(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got ledger.Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		DeviceLabel:    " \t\n ",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.Device != nil {
		t.Fatalf("device = %+v, want omitted", got.Device)
	}
}

func TestFlushResolvesDeploymentVersionPerFlush(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got ledger.Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	version := "  0.2.0  "
	flushOpts := func() Options {
		return Options{
			DBPath:            dbPath,
			StatePath:         filepath.Join(t.TempDir(), "stream-state.json"),
			CloudURL:          server.URL,
			OrganizationID:    "org_123",
			InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
			InstallToken:      "test-install-token",
			DeploymentVersion: func() string { return version },
			HTTPClient:        server.Client(),
		}
	}

	if err := Flush(context.Background(), flushOpts()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got.Device == nil || got.Device.DeploymentVersion != "0.2.0" {
		t.Fatalf("device = %+v, want deployment_version 0.2.0", got.Device)
	}

	// A later flush reflects a marker change (e.g. in-place upgrade) without
	// rebuilding the daemon's options. Fresh state path re-posts the decision.
	version = "0.3.0"
	if err := Flush(context.Background(), flushOpts()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got.Device == nil || got.Device.DeploymentVersion != "0.3.0" {
		t.Fatalf("device = %+v, want deployment_version 0.3.0", got.Device)
	}
}

func TestFlushDoesNotAdvanceCursorWhenHostedBackendFails(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err == nil {
		t.Fatal("Flush() error = nil, want hosted failure")
	}

	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file error = %v, want not exist", err)
	}
}

func TestFlushDefaultsStatePathBesideLedgerDB(t *testing.T) {
	t.Setenv(envStatePath, "")
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	statePath := filepath.Join(filepath.Dir(dbPath), "stream-state.json")
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil {
		t.Fatal("updated_after was not persisted")
	}
}

func TestFlushUsesUpdatedAfterCursor(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	updatedAfter := time.Now().Add(time.Hour).UTC()
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := SaveState(statePath, State{UpdatedAfter: &updatedAfter}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if called {
		t.Fatal("server was called despite cursor being newer than action")
	}
}

func TestLoadStateParsesAndTrimsFields(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := os.WriteFile(statePath, []byte(`{
  "updated_after": " 2026-05-31T10:11:12.123456789Z ",
  "action_id": "  act_123  "
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || state.UpdatedAfter.UTC().Format(time.RFC3339Nano) != "2026-05-31T10:11:12.123456789Z" {
		t.Fatalf("UpdatedAfter = %+v, want parsed timestamp", state.UpdatedAfter)
	}
	if state.ActionID != "act_123" {
		t.Fatalf("ActionID = %q, want %q", state.ActionID, "act_123")
	}
}

func TestLoadStateTreatsBlankTimestampAsUnset(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := os.WriteFile(statePath, []byte(`{"updated_after":" \t\n ","action_id":" act_123 "}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != nil {
		t.Fatalf("UpdatedAfter = %+v, want unset", state.UpdatedAfter)
	}
	if state.ActionID != "act_123" {
		t.Fatalf("ActionID = %q, want %q", state.ActionID, "act_123")
	}
}

func TestLoadStateRejectsInvalidTimestamp(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := os.WriteFile(statePath, []byte(`{"updated_after":"not-a-time"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := LoadState(statePath); err == nil {
		t.Fatal("LoadState() error = nil, want invalid timestamp failure")
	}
}

func testStore(t *testing.T) (*sqlite.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, dbPath
}

func capturePayloadServer(t *testing.T, got *ledger.Payload) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ledger.DefaultEndpoint {
			t.Fatalf("path = %q, want %q", r.URL.Path, ledger.DefaultEndpoint)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-install-token" {
			t.Fatalf("Authorization = %q, want bearer install token", got)
		}
		if err := json.NewDecoder(r.Body).Decode(got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
}

func saveTestDecision(t *testing.T, store *sqlite.Store, sessionID, toolUseID string) {
	t.Helper()
	_, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     sessionID,
		Agent:         "claude",
		CWD:           "/tmp/project",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     toolUseID,
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		ReasonCode: "OBSERVE_MODE",
		Reason:     "Allowed in observe mode",
		RiskEvent: risk.RiskEvent{
			Operation:      "read",
			OperationClass: "read",
			ResourceClass:  "file",
		},
	})
	if err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}
}
