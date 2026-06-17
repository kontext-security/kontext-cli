package managedstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func TestFlushPostsLedgerBatchWithInstallationIdentity(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		DeviceLabel:    "michel-macbook",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, SchemaVersion)
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
	if state.LastHeartbeatAttemptAt == "" || state.LastHeartbeatAt == "" {
		t.Fatalf("heartbeat state = %+v, want ledger success to count as heartbeat", state)
	}
}

func TestFlushOmitsBlankDeviceLabel(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
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

	var got Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	version := "  0.2.0  "
	flushOpts := func() Options {
		return Options{
			DBPath:            dbPath,
			StatePath:         filepath.Join(t.TempDir(), "stream-state.json"),
			CloudURL:          server.URL,
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

func TestFlushCapsBatchLimitBeforePosting(t *testing.T) {
	store, dbPath := testStore(t)
	for i := 0; i < 80; i++ {
		saveTestDecision(t, store, fmt.Sprintf("session-%03d", i), fmt.Sprintf("toolu_%03d", i))
	}

	var got Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1000,
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if len(got.Actions) > DefaultBatchLimit {
		t.Fatalf("posted %d actions, want at most %d", len(got.Actions), DefaultBatchLimit)
	}
}

func TestFlushRetriesWithSmallerBatchWhenHostedBackendRejectsSize(t *testing.T) {
	store, dbPath := testStore(t)
	for i := 0; i < 4; i++ {
		saveTestDecision(t, store, fmt.Sprintf("session-%03d", i), fmt.Sprintf("toolu_%03d", i))
	}

	var actionCounts []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got Payload
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		actionCounts = append(actionCounts, len(got.Actions))
		if len(actionCounts) == 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write([]byte(`{"message":"payload too large"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     4,
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if len(actionCounts) != 2 {
		t.Fatalf("request count = %d, want 2", len(actionCounts))
	}
	if actionCounts[0] <= actionCounts[1] {
		t.Fatalf("action counts = %v, want retry with a smaller batch", actionCounts)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil {
		t.Fatal("updated_after was not persisted after smaller retry")
	}
}

func TestFlushReportsHostedValidationBody(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"authorization_actions must contain no more than 1000 records"}`))
	}))
	t.Cleanup(server.Close)

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	if !strings.Contains(err.Error(), "status 400") ||
		!strings.Contains(err.Error(), "authorization_actions must contain no more than 1000 records") {
		t.Fatalf("Flush() error = %q, want status and response body", err.Error())
	}
}

func TestFlushRedactsHostedValidationBody(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"api_key":"raw-api-key","client_secret":"raw-client-secret","install_token":"raw-install-token","password":"raw-password","secret":"raw-secret","token":"raw-token","message":"Bearer raw-bearer"}`))
	}))
	t.Cleanup(server.Close)

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	for _, secret := range []string{
		"raw-api-key",
		"raw-client-secret",
		"raw-install-token",
		"raw-password",
		"raw-secret",
		"raw-token",
		"raw-bearer",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Flush() error = %q, want %q redacted", err.Error(), secret)
		}
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("Flush() error = %q, want hosted body secrets redacted", err.Error())
	}
}

func TestFlushDoesNotAdvanceCursorPastHostedRejectedMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"schema validation failed"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file error = %v, want not exist", err)
	}
}

func TestFlushAdvancesCursorPastOversizedMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveLargeTestDecision(t, store, "session-1", "toolu_1")

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want oversized minimum batch diagnostic")
	}
	if !strings.Contains(err.Error(), "advanced cursor past oversized minimum batch") {
		t.Fatalf("Flush() error = %q, want oversized skip diagnostic", err.Error())
	}
	if called {
		t.Fatal("server was called despite oversized local minimum batch")
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || state.ActionID == "" {
		t.Fatalf("state = %+v, want cursor advanced", state)
	}
}

func TestFlushPreservesHeartbeatStatePastOversizedMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveLargeTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	lastAttempt := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339Nano)
	lastSuccess := time.Now().Add(-90 * time.Second).UTC().Format(time.RFC3339Nano)
	if err := SaveState(statePath, State{
		LastHeartbeatAttemptAt: lastAttempt,
		LastHeartbeatAt:        lastSuccess,
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want oversized minimum batch diagnostic")
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || state.ActionID == "" {
		t.Fatalf("state = %+v, want cursor advanced", state)
	}
	if state.LastHeartbeatAttemptAt != lastAttempt || state.LastHeartbeatAt != lastSuccess {
		t.Fatalf("heartbeat state = %+v, want attempt %q success %q", state, lastAttempt, lastSuccess)
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

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	updatedAfter := time.Now().Add(time.Hour).UTC()
	if err := SaveState(statePath, State{
		UpdatedAfter:           &updatedAfter,
		LastHeartbeatAttemptAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
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

func TestFlushPostsHeartbeatWhenNoActionsArePending(t *testing.T) {
	_, dbPath := testStore(t)

	var got Payload
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	onFlushSuccessCalled := false
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:            dbPath,
		StatePath:         statePath,
		CloudURL:          server.URL,
		InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:      "test-install-token",
		DeviceLabel:       "michel-macbook",
		HeartbeatInterval: time.Minute,
		HTTPClient:        server.Client(),
		OnFlushSuccess:    func() { onFlushSuccessCalled = true },
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, SchemaVersion)
	}
	if got.InstallationID != "ins_0123456789abcdefghijklmnopqrstuv" {
		t.Fatalf("installation_id = %q", got.InstallationID)
	}
	if got.Device == nil || got.Device.Label != "michel-macbook" {
		t.Fatalf("device = %+v", got.Device)
	}
	if len(got.Sessions) != 0 || len(got.Actions) != 0 || len(got.Receipts) != 0 {
		t.Fatalf("heartbeat counts = sessions %d actions %d receipts %d, want all zero", len(got.Sessions), len(got.Actions), len(got.Receipts))
	}
	if !onFlushSuccessCalled {
		t.Fatal("OnFlushSuccess was not called for accepted heartbeat")
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != nil || state.ActionID != "" {
		t.Fatalf("state = %+v, want heartbeat not to advance ledger cursor", state)
	}
	if state.LastHeartbeatAttemptAt == "" || state.LastHeartbeatAt == "" {
		t.Fatalf("heartbeat state = %+v, want attempt and success persisted", state)
	}
}

func TestFlushSkipsHeartbeatBeforeInterval(t *testing.T) {
	_, dbPath := testStore(t)
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := SaveState(statePath, State{
		LastHeartbeatAttemptAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:            dbPath,
		StatePath:         statePath,
		CloudURL:          server.URL,
		InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:      "test-install-token",
		HeartbeatInterval: time.Minute,
		HTTPClient:        server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if called {
		t.Fatal("server was called before heartbeat interval elapsed")
	}
}

func TestFlushPersistsHeartbeatAttemptWhenHostedBackendFails(t *testing.T) {
	_, dbPath := testStore(t)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	opts := Options{
		DBPath:            dbPath,
		StatePath:         statePath,
		CloudURL:          server.URL,
		InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:      "test-install-token",
		HeartbeatInterval: time.Minute,
		HTTPClient:        server.Client(),
	}
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want hosted failure")
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.LastHeartbeatAttemptAt == "" {
		t.Fatalf("state = %+v, want failed attempt persisted", state)
	}
	if state.LastHeartbeatAt != "" {
		t.Fatalf("state = %+v, want no successful heartbeat", state)
	}

	if err := Flush(context.Background(), opts); err != nil {
		t.Fatalf("second Flush() error = %v, want throttled no-op", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want failed heartbeat throttled", requests)
	}
}

func TestStatePersistsUpdatedAfterAsRFC3339String(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	updatedAfter := time.Date(2026, 6, 8, 12, 20, 7, 853885000, time.UTC)
	if err := SaveState(statePath, State{UpdatedAfter: &updatedAfter, ActionID: "act_123"}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := string(raw); !strings.Contains(got, `"updated_after": "2026-06-08T12:20:07.853885Z"`) {
		t.Fatalf("state json = %s, want RFC3339 updated_after string", got)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || !state.UpdatedAfter.Equal(updatedAfter) || state.ActionID != "act_123" {
		t.Fatalf("LoadState() = %+v, want typed cursor", state)
	}
}

func TestParseStateUpdatedAfterAcceptsLegacyTimestampFormats(t *testing.T) {
	for _, value := range []string{
		"2026-06-08T12:20:07.853885",
		"2026-06-08 12:20:07.853885",
	} {
		parsed, err := parseStateUpdatedAfter(value)
		if err != nil {
			t.Fatalf("parseStateUpdatedAfter(%q) error = %v", value, err)
		}
		if got := parsed.UTC().Format(time.RFC3339Nano); got != "2026-06-08T12:20:07.853885Z" {
			t.Fatalf("parseStateUpdatedAfter(%q) = %q", value, got)
		}
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

func capturePayloadServer(t *testing.T, got *Payload) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultEndpoint {
			t.Fatalf("path = %q, want %q", r.URL.Path, DefaultEndpoint)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-install-token" {
			t.Fatalf("Authorization = %q, want bearer install token", got)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		// New agents must not send the legacy organization_id claim — the
		// install token alone binds the batch to its org.
		if strings.Contains(string(raw), `"organization_id"`) {
			t.Fatalf("payload contains organization_id claim: %s", raw)
		}
		if err := json.Unmarshal(raw, got); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
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

func saveLargeTestDecision(t *testing.T, store *sqlite.Store, sessionID, toolUseID string) {
	t.Helper()
	_, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     sessionID,
		Agent:         "claude",
		CWD:           "/tmp/project",
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolUseID:     toolUseID,
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		ReasonCode: "OBSERVE_MODE",
		Reason:     "Allowed in observe mode",
		RiskEvent: risk.RiskEvent{
			Operation:      "write",
			OperationClass: "write",
			ResourceClass:  "file",
			CommandSummary: strings.Repeat("x", MaxPayloadBytes),
		},
	})
	if err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}
}
