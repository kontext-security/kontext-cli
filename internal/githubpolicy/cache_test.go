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
)

func testSnapshot(epoch int, hash string) Snapshot {
	return Snapshot{
		SchemaVersion:  SchemaVersion,
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

	snapshot, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token")
	if err != nil {
		t.Fatalf("FetchSnapshot() error = %v", err)
	}
	if snapshot.Epoch != 3 || snapshot.Hash != "hash-3" || len(snapshot.Rules) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestFetchSnapshotRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxSnapshotBodyBytes+1))
	}))
	t.Cleanup(server.Close)

	_, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "test-install-token")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("FetchSnapshot() error = %v, want explicit size-limit failure", err)
	}
}

func TestFetchSnapshotRejectsUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	if _, err := FetchSnapshot(context.Background(), server.Client(), server.URL, "revoked"); err == nil {
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

func TestRunRefreshesUntilCancelled(t *testing.T) {
	fetches := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches <- struct{}{}
		_ = json.NewEncoder(w).Encode(testSnapshot(3, "hash-3"))
	}))
	t.Cleanup(server.Close)

	cache := NewCache(filepath.Join(t.TempDir(), "github-policy-snapshot.json"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, RunOptions{
			Cache:        cache,
			CloudURL:     server.URL,
			InstallToken: "test-install-token",
			Interval:     10 * time.Millisecond,
			HTTPClient:   server.Client(),
		})
		close(done)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-fetches:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for refresh fetches")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not stop on context cancellation")
	}

	if _, _, ok := cache.CurrentSnapshot(); !ok {
		t.Fatal("cache should hold a snapshot after refresh")
	}
}
