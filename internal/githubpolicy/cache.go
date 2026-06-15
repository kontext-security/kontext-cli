package githubpolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultRefreshInterval is how often the managed daemon re-fetches the
// snapshot. Hash-unchanged responses are cheap: they only bump freshness.
const DefaultRefreshInterval = 60 * time.Second

const envRefreshInterval = "KONTEXT_GITHUB_POLICY_REFRESH_INTERVAL"

// Status describes how trustworthy the cached snapshot currently is. A stale
// snapshot keeps being evaluated — stale-but-deterministic beats unavailable —
// and the staleness is recorded on every decision.
type Status struct {
	// FetchedAt is when the cached snapshot was last confirmed by the cloud
	// (fetch succeeded, whether or not the hash changed).
	FetchedAt time.Time `json:"fetched_at"`
	// Stale is true when the most recent fetch attempt failed and the cache
	// is serving the last known snapshot.
	Stale bool `json:"stale"`
	// LastError holds the most recent fetch failure, if any.
	LastError string `json:"last_error,omitempty"`
}

// SnapshotProvider is what the guard runtime consumes: the current snapshot,
// its freshness, and whether a snapshot exists at all.
type SnapshotProvider interface {
	CurrentSnapshot() (Snapshot, Status, bool)
}

// Cache holds the per-installation snapshot in memory and mirrors it to disk
// so the policy survives daemon restarts and cloud outages.
type Cache struct {
	path string

	mu       sync.RWMutex
	snapshot Snapshot
	status   Status
	loaded   bool
}

type cacheFile struct {
	SchemaVersion string   `json:"schema_version"`
	FetchedAt     string   `json:"fetched_at"`
	Snapshot      Snapshot `json:"snapshot"`
}

func NewCache(path string) *Cache {
	return &Cache{path: path}
}

// DefaultCachePathForDB stores the snapshot next to the guard database, the
// same convention managedstream uses for its cursor state.
func DefaultCachePathForDB(dbPath string) string {
	if dbPath = strings.TrimSpace(dbPath); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "github-policy-snapshot.json")
	}
	return "github-policy-snapshot.json"
}

func (c *Cache) CurrentSnapshot() (Snapshot, Status, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshot, c.status, c.loaded
}

// LoadPersisted primes the cache from disk so evaluation works before the
// first fetch completes. The persisted snapshot starts out stale until the
// cloud confirms it.
func (c *Cache) LoadPersisted() error {
	if c.path == "" {
		return nil
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var file cacheFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	if file.Snapshot.SchemaVersion != SchemaVersion {
		return nil
	}
	fetchedAt, _ := time.Parse(time.RFC3339Nano, file.FetchedAt)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = file.Snapshot
	c.status = Status{FetchedAt: fetchedAt, Stale: true, LastError: "persisted snapshot not yet confirmed by cloud"}
	c.loaded = true
	return nil
}

// Apply installs a freshly fetched snapshot. When the hash is unchanged the
// rules are not re-applied or re-persisted; only freshness is updated.
func (c *Cache) Apply(snapshot Snapshot, fetchedAt time.Time) error {
	c.mu.Lock()
	unchanged := c.loaded && c.snapshot.Hash == snapshot.Hash
	if !unchanged {
		c.snapshot = snapshot
	}
	c.status = Status{FetchedAt: fetchedAt}
	c.loaded = true
	c.mu.Unlock()
	if unchanged {
		return nil
	}
	return c.persist(snapshot, fetchedAt)
}

// MarkFetchFailed records that the latest refresh failed; the cached snapshot
// keeps serving evaluations.
func (c *Cache) MarkFetchFailed(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Stale = true
	if err != nil {
		c.status.LastError = err.Error()
	}
}

func (c *Cache) persist(snapshot Snapshot, fetchedAt time.Time) error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cacheFile{
		SchemaVersion: SchemaVersion,
		FetchedAt:     fetchedAt.UTC().Format(time.RFC3339Nano),
		Snapshot:      snapshot,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(c.path), ".github-policy-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, c.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func DefaultIntervalFromEnv() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envRefreshInterval)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultRefreshInterval
}
