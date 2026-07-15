package endpointconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func TestCacheRestartRequiresServerConfirmation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "endpoint-configuration.json")
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	full := testResponse(t, payloadcapture.ModeFull)
	cache := NewCache(path)
	if err := cache.Apply(FetchResult{Response: &full}, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %o", info.Mode().Perm())
	}

	restored := NewCache(path)
	if err := restored.Load(); err != nil {
		t.Fatal(err)
	}
	if snapshot := restored.Current(); snapshot.Config.PayloadCaptureMode != payloadcapture.ModeSummary || snapshot.LastKnownGood == nil || !snapshot.Status.Stale {
		t.Fatalf("unconfirmed snapshot = %#v", snapshot)
	}
	if err := restored.Apply(FetchResult{NotModified: true, ETag: full.ConfigIdentity}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if snapshot := restored.Current(); snapshot.Config.PayloadCaptureMode != payloadcapture.ModeFull || snapshot.ConfigIdentity != full.ConfigIdentity {
		t.Fatalf("confirmed snapshot = %#v", snapshot)
	}
}

func TestCacheFailureFallsBackWithoutDiscardingConditionalValue(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	full := testResponse(t, payloadcapture.ModeFull)
	if err := cache.Apply(FetchResult{Response: &full}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	cache.MarkFailed(errors.New("offline"), time.Now().UTC())
	snapshot := cache.Current()
	if snapshot.Config.PayloadCaptureMode != payloadcapture.ModeSummary || snapshot.ConfigIdentity != full.ConfigIdentity || snapshot.LastKnownGood == nil || !snapshot.Status.Stale || snapshot.FallbackReason != "refresh_failed" {
		t.Fatalf("failed snapshot = %#v", snapshot)
	}
	if cache.ConditionalIdentity() != full.ConfigIdentity {
		t.Fatalf("ConditionalIdentity() = %q", cache.ConditionalIdentity())
	}
}

func TestCacheRejectsMismatchedNotModified(t *testing.T) {
	cache := NewCache("")
	if err := cache.Apply(FetchResult{NotModified: true, ETag: strings.Repeat("a", 64)}, time.Now().UTC()); err == nil {
		t.Fatal("Apply() error = nil")
	}
}

func TestRefresherFailureNotifiesSafeDefault(t *testing.T) {
	cache := NewCache("")
	full := testResponse(t, payloadcapture.ModeFull)
	if err := cache.Apply(FetchResult{Response: &full}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	changed := make(chan Snapshot, 1)
	refresher := Refresher{
		Cache: cache,
		TokenSource: func(context.Context) (string, error) {
			return "", errors.New("token unavailable")
		},
		OnChanged: func(snapshot Snapshot) { changed <- snapshot },
	}
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil")
	}
	select {
	case snapshot := <-changed:
		if snapshot.Config.PayloadCaptureMode != payloadcapture.ModeSummary {
			t.Fatalf("notified config = %#v", snapshot.Config)
		}
	default:
		t.Fatal("OnChanged was not called")
	}
}
