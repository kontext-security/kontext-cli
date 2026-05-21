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
)

func TestFlushPostsLedgerBatchWithInstallationIdentity(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got Payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultEndpoint {
			t.Fatalf("path = %q, want %q", r.URL.Path, DefaultEndpoint)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		DeviceLabel:    "michel-macbook",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, SchemaVersion)
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
	if len(got.Sessions) != 1 || len(got.Actions) != 1 || len(got.Receipts) != 1 {
		t.Fatalf("batch counts = sessions %d actions %d receipts %d", len(got.Sessions), len(got.Actions), len(got.Receipts))
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == "" {
		t.Fatal("updated_after was not persisted")
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
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	statePath := filepath.Join(filepath.Dir(dbPath), "stream-state.json")
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == "" {
		t.Fatal("updated_after was not persisted")
	}
}

func TestFlushUsesUpdatedAfterCursor(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := SaveState(statePath, State{UpdatedAfter: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}); err != nil {
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
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if called {
		t.Fatal("server was called despite cursor being newer than action")
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
