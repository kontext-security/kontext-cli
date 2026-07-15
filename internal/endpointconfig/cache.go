package endpointconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

const (
	DefaultRefreshInterval = time.Minute
	DefaultMaxBackoff      = 10 * time.Minute
)

var defaultConfig = Config{PayloadCaptureMode: payloadcapture.ModeSummary}

type Status struct {
	FetchedAt     time.Time
	LastAttemptAt time.Time
	Stale         bool
	LastError     string
	Invalid       bool
}

type Snapshot struct {
	Config         Config
	Configured     Config
	ConfigIdentity string
	Confirmed      bool
	FallbackReason string
	LastKnownGood  *Response
	Status         Status
}

type cacheFile struct {
	Version   int       `json:"version"`
	FetchedAt string    `json:"fetchedAt"`
	Response  *Response `json:"response"`
}

type Cache struct {
	path string
	now  func() time.Time

	mu       sync.RWMutex
	fetched  time.Time
	active   *Response
	lastGood *Response
	status   Status
}

func NewCache(path string) *Cache {
	return &Cache{path: path, now: time.Now}
}

func DefaultCachePathForDB(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "endpoint-config.json")
}

// Load restores only the conditional value. The effective configuration stays
// at the privacy-safe default until the server confirms it with 200 or 304.
func (c *Cache) Load() error {
	if c.path == "" {
		return nil
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("endpoint configuration cache: read: %w", err)
	}
	var file cacheFile
	if err := decodeStrict(strings.NewReader(string(data)), &file); err != nil {
		return fmt.Errorf("endpoint configuration cache: %w", err)
	}
	if file.Version != 1 || file.Response == nil {
		return errors.New("endpoint configuration cache: invalid cache shape")
	}
	if err := file.Response.Validate(); err != nil {
		return fmt.Errorf("endpoint configuration cache: %w", err)
	}
	fetchedAt, err := time.Parse(time.RFC3339Nano, file.FetchedAt)
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: invalid fetchedAt: %w", err)
	}
	c.mu.Lock()
	c.fetched = fetchedAt
	c.active = nil
	c.lastGood = cloneResponse(file.Response)
	c.status = Status{FetchedAt: fetchedAt, Stale: true, LastError: "persisted configuration not yet confirmed"}
	c.mu.Unlock()
	return nil
}

func (c *Cache) Apply(result FetchResult, fetchedAt time.Time) error {
	if fetchedAt.IsZero() {
		fetchedAt = c.now().UTC()
	}
	c.mu.RLock()
	lastGood := cloneResponse(c.lastGood)
	c.mu.RUnlock()
	var confirmed *Response
	switch {
	case result.NotModified:
		if lastGood == nil || result.ETag == "" || result.ETag != lastGood.ConfigIdentity {
			return errors.New("endpoint configuration cache: not-modified result does not match last-known-good config")
		}
		confirmed = lastGood
	case result.Response != nil:
		if err := result.Response.Validate(); err != nil {
			return err
		}
		confirmed = cloneResponse(result.Response)
	default:
		return errors.New("endpoint configuration cache: result has no configuration")
	}
	file := cacheFile{
		Version:   1,
		FetchedAt: fetchedAt.UTC().Format(time.RFC3339Nano),
		Response:  cloneResponse(confirmed),
	}
	if err := c.persist(file); err != nil {
		return err
	}
	c.mu.Lock()
	c.fetched = fetchedAt
	c.active = cloneResponse(confirmed)
	c.lastGood = cloneResponse(confirmed)
	c.status = Status{FetchedAt: fetchedAt, LastAttemptAt: fetchedAt}
	c.mu.Unlock()
	return nil
}

// MarkFailed immediately returns the effective config to summary while
// retaining the validated value solely for conditional revalidation.
func (c *Cache) MarkFailed(err error, attemptedAt time.Time) {
	if attemptedAt.IsZero() {
		attemptedAt = c.now().UTC()
	}
	c.mu.Lock()
	c.active = nil
	c.status.FetchedAt = c.fetched
	c.status.LastAttemptAt = attemptedAt
	c.status.Stale = true
	if err != nil {
		c.status.LastError = err.Error()
	}
	c.mu.Unlock()
}

func (c *Cache) MarkInvalid(err error) {
	c.MarkFailed(err, c.now().UTC())
	c.mu.Lock()
	c.status.Invalid = true
	c.mu.Unlock()
}

func (c *Cache) Current() Snapshot {
	c.mu.RLock()
	active := cloneResponse(c.active)
	lastGood := cloneResponse(c.lastGood)
	status := c.status
	c.mu.RUnlock()
	if active == nil {
		configured := defaultConfig
		identity := ""
		fallbackReason := "no_confirmed_config"
		if lastGood != nil {
			configured = lastGood.Config
			identity = lastGood.ConfigIdentity
			fallbackReason = "awaiting_confirmation"
		}
		if !status.LastAttemptAt.IsZero() && status.Stale {
			fallbackReason = "refresh_failed"
		}
		if status.Invalid {
			fallbackReason = "invalid_cache"
		}
		return Snapshot{
			Config:         defaultConfig,
			Configured:     configured,
			ConfigIdentity: identity,
			FallbackReason: fallbackReason,
			LastKnownGood:  lastGood,
			Status:         status,
		}
	}
	return Snapshot{
		Config:         active.Config,
		Configured:     active.Config,
		ConfigIdentity: active.ConfigIdentity,
		Confirmed:      true,
		LastKnownGood:  lastGood,
		Status:         status,
	}
}

func (c *Cache) ConditionalIdentity() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastGood == nil {
		return ""
	}
	return c.lastGood.ConfigIdentity
}

func (c *Cache) persist(file cacheFile) error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("endpoint configuration cache: create directory: %w", err)
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: encode: %w", err)
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".endpoint-config-*.tmp")
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("endpoint configuration cache: set permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("endpoint configuration cache: write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("endpoint configuration cache: sync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("endpoint configuration cache: close: %w", err)
	}
	if err := os.Rename(temporaryPath, c.path); err != nil {
		return fmt.Errorf("endpoint configuration cache: replace: %w", err)
	}
	cleanup = false
	directory, err := os.Open(filepath.Dir(c.path))
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: open directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("endpoint configuration cache: sync directory: %w", err)
	}
	return nil
}

func cloneResponse(input *Response) *Response {
	if input == nil {
		return nil
	}
	clone := *input
	return &clone
}

type TokenSource func(context.Context) (string, error)

type Refresher struct {
	Client         *Client
	Cache          *Cache
	TokenSource    TokenSource
	InstallationID string
	Interval       time.Duration
	MaxBackoff     time.Duration
	Now            func() time.Time
	Jitter         func(time.Duration) time.Duration
	OnChanged      func(Snapshot)
}

func (r *Refresher) Refresh(ctx context.Context) error {
	if r.Client == nil || r.Cache == nil || r.TokenSource == nil {
		return r.fail(errors.New("endpoint configuration refresher is not configured"))
	}
	token, err := r.TokenSource(ctx)
	if err != nil {
		return r.fail(err)
	}
	result, err := r.Client.Fetch(ctx, token, r.InstallationID, r.Cache.ConditionalIdentity())
	if err != nil {
		return r.fail(err)
	}
	if err := r.Cache.Apply(result, r.now()); err != nil {
		return r.fail(err)
	}
	r.notify()
	return nil
}

func (r *Refresher) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	maxBackoff := r.MaxBackoff
	if maxBackoff < interval {
		maxBackoff = DefaultMaxBackoff
		if maxBackoff < interval {
			maxBackoff = 10 * interval
		}
	}
	delay := interval
	for {
		if ctx.Err() != nil {
			return
		}
		if err := r.Refresh(ctx); err == nil {
			delay = interval
		} else if delay < maxBackoff {
			delay *= 2
			if delay > maxBackoff {
				delay = maxBackoff
			}
		}
		timer := time.NewTimer(r.jitter(delay))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (r *Refresher) fail(err error) error {
	if r.Cache != nil {
		r.Cache.MarkFailed(err, r.now())
		r.notify()
	}
	return err
}

func (r *Refresher) notify() {
	if r.OnChanged != nil && r.Cache != nil {
		r.OnChanged(r.Cache.Current())
	}
}

func (r *Refresher) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Refresher) jitter(delay time.Duration) time.Duration {
	if r.Jitter != nil {
		return r.Jitter(delay)
	}
	// Spread retry traffic over [75%, 125%] without changing the configured
	// steady-state interval or the bounded exponential backoff.
	return delay*3/4 + time.Duration(rand.Int64N(int64(delay/2)+1))
}
