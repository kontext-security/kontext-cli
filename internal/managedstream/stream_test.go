package managedstream

import (
	"context"
	"encoding/json"
	"fmt"
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
		OrganizationID: "org_123",
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
	if state.UpdatedAfter == "" {
		t.Fatal("updated_after was not persisted")
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

	var got Payload
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
		OrganizationID: "org_123",
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
		OrganizationID: "org_123",
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
	if state.UpdatedAfter == "" {
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

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
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
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != "" || state.ActionID != "" || state.FailureKind != failureKindTerminalConfig {
		t.Fatalf("state = %+v, want minimum hosted validation failure paused without cursor advance", state)
	}
}

func TestFlushOrgMismatch400EntersCooldownAndDoesNotRepost(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"authorization ledger organization_id does not match authenticated principal","error":"Bad Request","statusCode":400}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	opts := Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want terminal hosted failure")
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want one terminal attempt without smaller-batch retries", requests)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.FailureKind != failureKindTerminalConfig || state.FailureStatus != http.StatusBadRequest {
		t.Fatalf("state failure = kind %q status %d, want terminal config 400", state.FailureKind, state.FailureStatus)
	}
	if state.CooldownUntil == "" {
		t.Fatalf("state = %+v, want cooldown", state)
	}
	if state.UpdatedAfter != "" || state.ActionID != "" {
		t.Fatalf("state = %+v, want cooldown without cursor advance", state)
	}

	saveTestDecision(t, store, "session-2", "toolu_2")
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want cooldown pause diagnostic")
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want cooldown to skip hosted repost", requests)
	}
	state, err = LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != "" || state.ActionID != "" {
		t.Fatalf("state = %+v, want cooldown without cursor advance", state)
	}
}

func TestFlushCredentialChangeClearsTerminalCooldown(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") == "Bearer fixed-install-token" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"authorization ledger organization_id does not match authenticated principal"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	opts := Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "stale-install-token",
		HTTPClient:     server.Client(),
	}
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want terminal hosted failure")
	}

	opts.InstallToken = "fixed-install-token"
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatalf("Flush() after credential change error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d, want retry after credential change", requests)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.FailureKind != "" || state.CooldownUntil != "" {
		t.Fatalf("state = %+v, want terminal cooldown cleared after success", state)
	}
	if state.UpdatedAfter == "" || state.ActionID == "" {
		t.Fatalf("state = %+v, want cursor advanced after success", state)
	}
}

func TestFlushPausesGeneric400WithoutAdvancingCursor(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")
	saveTestDecision(t, store, "session-2", "toolu_2")

	var actionCounts []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		actionCounts = append(actionCounts, len(payload.Actions))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"schema validation failed"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	opts := Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want terminal hosted failure")
	}
	if len(actionCounts) != 1 || actionCounts[0] <= 1 {
		t.Fatalf("posted action counts = %v, want one terminal attempt without smaller-batch retries", actionCounts)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.FailureKind != failureKindTerminalConfig || state.UpdatedAfter != "" || state.ActionID != "" {
		t.Fatalf("state = %+v, want terminal cooldown without cursor advance", state)
	}

	firstFlushRequests := len(actionCounts)
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want cooldown pause diagnostic")
	}
	if len(actionCounts) != firstFlushRequests {
		t.Fatalf("posted action counts after second flush = %v, want no hosted repost during cooldown", actionCounts)
	}
	state, err = LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != "" || state.ActionID != "" {
		t.Fatalf("state = %+v, want cursor still paused", state)
	}
}

func TestFlushScalarSizeLike400EntersCooldownWithoutBatchRetries(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")
	saveTestDecision(t, store, "session-2", "toolu_2")

	var actionCounts []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		actionCounts = append(actionCounts, len(payload.Actions))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"installation_id must contain no more than 64 characters"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want terminal hosted failure")
	}
	if len(actionCounts) != 1 || actionCounts[0] <= 1 {
		t.Fatalf("posted action counts = %v, want one terminal attempt without smaller-batch retries", actionCounts)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.FailureKind != failureKindTerminalConfig || state.UpdatedAfter != "" || state.ActionID != "" {
		t.Fatalf("state = %+v, want terminal cooldown without cursor advance", state)
	}
}

func TestFlushDoesNotAdvanceCursorForAuthFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			store, dbPath := testStore(t)
			saveTestDecision(t, store, "session-1", "toolu_1")

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"message":"auth failed"}`))
			}))
			t.Cleanup(server.Close)

			statePath := filepath.Join(t.TempDir(), "stream-state.json")
			err := Flush(context.Background(), Options{
				DBPath:         dbPath,
				StatePath:      statePath,
				CloudURL:       server.URL,
				OrganizationID: "org_123",
				InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
				InstallToken:   "test-install-token",
				HTTPClient:     server.Client(),
			})
			if err == nil {
				t.Fatalf("Flush() error = nil, want status %d failure", status)
			}
			if _, err := os.Stat(statePath); !os.IsNotExist(err) {
				t.Fatalf("state file error = %v, want not exist", err)
			}
		})
	}
}

func TestFlushDoesNotAdvanceCursorForUnprocessableValidation(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"installation_id is invalid"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want terminal hosted failure")
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want one terminal attempt", requests)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != "" || state.ActionID != "" || state.FailureKind != failureKindTerminalConfig {
		t.Fatalf("state = %+v, want terminal cooldown without cursor advance", state)
	}
}

func TestFlushReportsMalformedCooldownState(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	opts := Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}
	if err := SaveState(statePath, State{
		FailureKind:   failureKindTerminalConfig,
		FailureConfig: configFingerprint(opts),
		CooldownUntil: "not-a-timestamp",
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	err := Flush(context.Background(), opts)
	if err == nil {
		t.Fatal("Flush() error = nil, want malformed cooldown state")
	}
	if !strings.Contains(err.Error(), "parse managed stream cooldown state") {
		t.Fatalf("Flush() error = %q, want malformed cooldown state", err.Error())
	}
	if requests != 0 {
		t.Fatalf("request count = %d, want no hosted post with malformed cooldown state", requests)
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
		OrganizationID: "org_123",
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

func TestFlushDoesNotAdvanceCursorPastGenericHostedRejectedMinimumBatch(t *testing.T) {
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
		OrganizationID: "org_123",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	if !strings.Contains(err.Error(), "entered cooldown after terminal hosted ingest failure") {
		t.Fatalf("Flush() error = %q, want terminal cooldown diagnostic", err.Error())
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != "" || state.ActionID != "" || state.FailureKind != failureKindTerminalConfig {
		t.Fatalf("state = %+v, want terminal cooldown without cursor advance", state)
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
		OrganizationID: "org_123",
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
	if state.UpdatedAfter == "" || state.ActionID == "" {
		t.Fatalf("state = %+v, want cursor advanced", state)
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
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if called {
		t.Fatal("server was called despite cursor being newer than action")
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

func TestStateJSONBoundaryPreservesCursorOnlyAndFailureShape(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := os.WriteFile(statePath, []byte(`{"updated_after":"2026-06-08T12:20:07.853885Z","action_id":"action-123"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != "2026-06-08T12:20:07.853885Z" || state.ActionID != "action-123" {
		t.Fatalf("state = %+v, want cursor-only persisted shape", state)
	}
	if state.FailureKind != "" || state.FailureConfig != "" {
		t.Fatalf("state = %+v, want no failure state from cursor-only shape", state)
	}

	state.FailureKind = failureKindTerminalConfig
	state.FailureStatus = http.StatusBadRequest
	state.FailureMessage = "organization mismatch"
	state.FailureConfig = streamConfigFingerprint("config-key")
	state.FailureCount = 2
	state.CooldownUntil = "2026-06-08T12:35:07.853885Z"
	if err := SaveState(statePath, state); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var persisted struct {
		UpdatedAfter   string `json:"updated_after"`
		ActionID       string `json:"action_id"`
		FailureKind    string `json:"failure_kind"`
		FailureStatus  int    `json:"failure_status"`
		FailureMessage string `json:"failure_message"`
		FailureConfig  string `json:"failure_config"`
		FailureCount   int    `json:"failure_count"`
		CooldownUntil  string `json:"cooldown_until"`
	}
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if persisted.FailureKind != "terminal_config" || persisted.FailureConfig != "config-key" {
		t.Fatalf("persisted state = %+v, want string failure fields", persisted)
	}
	if persisted.UpdatedAfter != state.UpdatedAfter || persisted.ActionID != state.ActionID ||
		persisted.FailureStatus != state.FailureStatus || persisted.FailureMessage != state.FailureMessage ||
		persisted.FailureCount != state.FailureCount || persisted.CooldownUntil != state.CooldownUntil {
		t.Fatalf("persisted state = %+v, want state fields preserved", persisted)
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
