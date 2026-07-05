package githubpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/providerpolicy"
)

func testSnapshot(epoch int, hash string) Snapshot {
	return Snapshot{
		SchemaVersion:  SchemaVersionV2,
		OrganizationID: testOrgID,
		ProviderKey:    "github",
		Mode:           ModeObserve,
		Epoch:          epoch,
		Hash:           hash,
		Rules:          []Rule{{ID: "rule-1", Layer: LayerOrg, SubjectID: testOrgID, Effect: EffectAllow}},
		GeneratedAt:    "2026-06-11T00:00:00.000Z",
	}
}

func TestFetchSnapshotSendsInstallTokenAndDecodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SnapshotEndpoint {
			t.Fatalf("path = %q, want %q", r.URL.Path, SnapshotEndpoint)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-install-token" {
			t.Fatalf("Authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(testSnapshot(3, "hash-3"))
	}))
	t.Cleanup(server.Close)

	snapshot, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", "ins_0123456789abcdefghijklmnopqrstuv")
	if err != nil {
		t.Fatalf("FetchSnapshot() error = %v", err)
	}
	if snapshot.Epoch != 3 || snapshot.Hash != "hash-3" || len(snapshot.Rules) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestFetchSnapshotRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, providerpolicy.MaxSnapshotBodyBytes+1))
	}))
	t.Cleanup(server.Close)

	_, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token", "ins_0123456789abcdefghijklmnopqrstuv")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("FetchSnapshot() error = %v, want explicit size-limit failure", err)
	}
}

func TestFetchSnapshotRejectsUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "revoked", ""); err == nil {
		t.Fatal("FetchSnapshot() with revoked token should fail")
	}
}

func TestCacheApplyPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-policy-snapshot.json")
	cache := NewCache(path)
	if err := cache.Apply(testSnapshot(3, "hash-3"), time.Now().UTC()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	reloaded := NewCache(path)
	if err := reloaded.LoadPersisted(); err != nil {
		t.Fatalf("LoadPersisted() error = %v", err)
	}
	snapshot, status, ok := reloaded.CurrentSnapshot()
	if !ok || snapshot.Hash != "hash-3" {
		t.Fatalf("CurrentSnapshot() = %+v, %v", snapshot, ok)
	}
	if !status.Stale {
		t.Fatal("persisted snapshot should start stale until the cloud confirms it")
	}
}

func TestCacheUnchangedHashSkipsReapply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-policy-snapshot.json")
	cache := NewCache(path)
	if err := cache.Apply(testSnapshot(3, "hash-3"), time.Now().UTC()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	// A second fetch with the same hash only refreshes status; the snapshot
	// (including its rule slice) stays in place.
	unchanged := testSnapshot(3, "hash-3")
	unchanged.Rules = nil // would wipe rules if re-applied
	if err := cache.Apply(unchanged, time.Now().UTC()); err != nil {
		t.Fatalf("Apply() unchanged error = %v", err)
	}
	snapshot, status, _ := cache.CurrentSnapshot()
	if len(snapshot.Rules) != 1 {
		t.Fatalf("rules were re-applied on unchanged hash: %+v", snapshot.Rules)
	}
	if status.Stale {
		t.Fatal("status should be fresh after a confirmed fetch")
	}
}

func TestCacheKeepsServingStaleSnapshotOnFetchFailure(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "github-policy-snapshot.json"))
	if err := cache.Apply(testSnapshot(3, "hash-3"), time.Now().UTC()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cache.MarkFetchFailed(context.DeadlineExceeded)

	snapshot, status, ok := cache.CurrentSnapshot()
	if !ok || snapshot.Hash != "hash-3" {
		t.Fatalf("CurrentSnapshot() after failure = %+v, %v", snapshot, ok)
	}
	if !status.Stale || status.LastError == "" {
		t.Fatalf("status = %+v, want stale with recorded error", status)
	}
}

func TestSnapshotDecodesPayloadCaptureMode(t *testing.T) {
	var withField Snapshot
	if err := json.Unmarshal([]byte(`{"schemaVersion":"github-policy-snapshot-v2","hash":"h","payloadCaptureMode":"full"}`), &withField); err != nil {
		t.Fatalf("unmarshal with field: %v", err)
	}
	if withField.PayloadCaptureMode != "full" {
		t.Fatalf("PayloadCaptureMode = %q, want %q", withField.PayloadCaptureMode, "full")
	}

	// Pre-capture server: field absent must decode to "" (normalized to
	// "summary" downstream), not an error.
	var withoutField Snapshot
	if err := json.Unmarshal([]byte(`{"schemaVersion":"github-policy-snapshot-v2","hash":"h"}`), &withoutField); err != nil {
		t.Fatalf("unmarshal without field: %v", err)
	}
	if withoutField.PayloadCaptureMode != "" {
		t.Fatalf("PayloadCaptureMode = %q, want empty", withoutField.PayloadCaptureMode)
	}
}

func TestCachePersistsPayloadCaptureModeAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-policy-snapshot.json")
	cache := NewCache(path)
	snapshot := testSnapshot(3, "hash-3")
	snapshot.PayloadCaptureMode = "full"
	if err := cache.Apply(snapshot, time.Now().UTC()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	reloaded := NewCache(path)
	if err := reloaded.LoadPersisted(); err != nil {
		t.Fatalf("LoadPersisted() error = %v", err)
	}
	persisted, _, ok := reloaded.CurrentSnapshot()
	if !ok || persisted.PayloadCaptureMode != "full" {
		t.Fatalf("persisted PayloadCaptureMode = %q, %v; want %q", persisted.PayloadCaptureMode, ok, "full")
	}
}

// Regression test for the hash-exclusion hazard: payloadCaptureMode is
// deliberately excluded from the server-side snapshot hash, so a mode flip
// arrives on a snapshot whose hash is UNCHANGED. The cache must adopt and
// persist it anyway — a hash-equality short-circuit that drops the new mode
// would freeze the org's capture directive until the next policy edit.
func TestCacheAdoptsAndPersistsModeChangeOnUnchangedHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-policy-snapshot.json")
	cache := NewCache(path)
	first := testSnapshot(3, "hash-3")
	first.PayloadCaptureMode = "summary"
	if err := cache.Apply(first, time.Now().UTC()); err != nil {
		t.Fatalf("Apply() first error = %v", err)
	}

	second := testSnapshot(3, "hash-3") // identical hash, only the mode flips
	second.PayloadCaptureMode = "full"
	if err := cache.Apply(second, time.Now().UTC()); err != nil {
		t.Fatalf("Apply() second error = %v", err)
	}

	snapshot, _, _ := cache.CurrentSnapshot()
	if snapshot.PayloadCaptureMode != "full" {
		t.Fatalf("in-memory PayloadCaptureMode = %q, want %q after mode flip on unchanged hash", snapshot.PayloadCaptureMode, "full")
	}

	reloaded := NewCache(path)
	if err := reloaded.LoadPersisted(); err != nil {
		t.Fatalf("LoadPersisted() error = %v", err)
	}
	persisted, _, ok := reloaded.CurrentSnapshot()
	if !ok || persisted.PayloadCaptureMode != "full" {
		t.Fatalf("persisted PayloadCaptureMode = %q, %v; want %q to survive restart", persisted.PayloadCaptureMode, ok, "full")
	}
}

// Snapshot.Mode (observe/enforce) is outside the server-side hash for the
// same reason payloadCaptureMode is — same hazard, same guarantee: a flip on
// an unchanged hash must be adopted and survive a restart.
func TestCacheAdoptsAndPersistsEnforcementModeChangeOnUnchangedHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-policy-snapshot.json")
	cache := NewCache(path)
	if err := cache.Apply(testSnapshot(3, "hash-3"), time.Now().UTC()); err != nil {
		t.Fatalf("Apply() first error = %v", err)
	}

	flipped := testSnapshot(3, "hash-3") // identical hash, only the mode flips
	flipped.Mode = ModeEnforce
	if err := cache.Apply(flipped, time.Now().UTC()); err != nil {
		t.Fatalf("Apply() flipped error = %v", err)
	}

	snapshot, _, _ := cache.CurrentSnapshot()
	if !snapshot.Enforce() {
		t.Fatalf("in-memory Mode = %q, want %q after flip on unchanged hash", snapshot.Mode, ModeEnforce)
	}

	reloaded := NewCache(path)
	if err := reloaded.LoadPersisted(); err != nil {
		t.Fatalf("LoadPersisted() error = %v", err)
	}
	persisted, _, ok := reloaded.CurrentSnapshot()
	if !ok || !persisted.Enforce() {
		t.Fatalf("persisted Mode = %q, %v; want %q to survive restart", persisted.Mode, ok, ModeEnforce)
	}
}
