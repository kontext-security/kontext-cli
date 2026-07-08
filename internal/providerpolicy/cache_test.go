package providerpolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clearTestConfig() Config {
	return Config{
		ProviderKey:      "testprov",
		CacheFileName:    "testprov-policy-snapshot.json",
		CacheTempPattern: ".testprov-policy-*.tmp",
		Schemas:          []SchemaSupport{{Version: "testprov-policy-snapshot-v1"}},
	}
}

func clearTestSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion:  "testprov-policy-snapshot-v1",
		OrganizationID: "org-1",
		ProviderKey:    "testprov",
		Mode:           ModeObserve,
		Epoch:          3,
		Hash:           "hash-3",
		Rules:          []Rule{{ID: "r1", Layer: LayerOrg, SubjectID: "org-1", Effect: EffectAllow}},
	}
}

func TestCacheKeepsSnapshotOnNotConfiguredFetch(t *testing.T) {
	// Contract: a 404 from the cloud (route not deployed / infra blip) must
	// NOT drop cached policy — deactivation is signaled by an EMPTY snapshot,
	// never by 404. The cache keeps serving, marked stale, and the persisted
	// mirror survives a daemon restart.
	path := filepath.Join(t.TempDir(), "testprov-policy-snapshot.json")
	cache := NewCache(path, clearTestConfig())
	if err := cache.Apply(clearTestSnapshot(), time.Now().UTC()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	cache.MarkFetchFailed(ErrNotConfigured)

	snapshot, status, ok := cache.CurrentSnapshot()
	if !ok || snapshot.Hash != "hash-3" {
		t.Fatalf("CurrentSnapshot() = %+v, %v — snapshot must survive a 404", snapshot, ok)
	}
	if !status.Stale {
		t.Fatal("status should be stale after an unconfirmed refresh")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("persisted mirror must survive a 404: %v", err)
	}
}
