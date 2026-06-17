package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

// A store with one decision so every Flush actually posts — an empty store
// short-circuits before hitting the server, which would reset the
// auth-failure counter without exercising it.
func seededStore(t *testing.T) string {
	t.Helper()
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "sess-auth-test", "tool-use-auth-test")
	return dbPath
}

func TestFlushDoesNotFireOnFlushSuccessWithoutPosting(t *testing.T) {
	// An empty flush never contacts the server and therefore proves nothing
	// about the token — it must not clear a "token rejected" breadcrumb on an
	// idle machine whose token is still revoked.
	_, dbPath := testStore(t)
	statePath := filepath.Join(filepath.Dir(dbPath), "state.json")
	if err := SaveState(statePath, State{
		LastHeartbeatAttemptAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	fired := false
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       "https://unreachable.invalid",
		InstallationID: "ins_test",
		InstallToken:   "any",
		Diagnostic:     diagnostic.New(nil, false),
		OnFlushSuccess: func() { fired = true },
	})
	if err != nil {
		t.Fatalf("Flush(empty store) error = %v", err)
	}
	if fired {
		t.Fatal("OnFlushSuccess fired for an empty flush that never posted")
	}
}

func TestRunFiresOnAuthFailureAfterConsecutive401s(t *testing.T) {
	dbPath := seededStore(t)
	dir := filepath.Dir(dbPath)

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "valid install token is required"})
	}))
	defer server.Close()

	authFired := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DBPath:         dbPath,
			StatePath:      filepath.Join(dir, "state.json"),
			CloudURL:       server.URL,
			InstallationID: "ins_test",
			InstallToken:   "revoked-token",
			Interval:       5 * time.Millisecond,
			HTTPClient:     server.Client(),
			Diagnostic:     diagnostic.New(nil, false),
			OnAuthFailure: func(status int) {
				select {
				case authFired <- status:
				default:
				}
			},
		})
	}()

	select {
	case status := <-authFired:
		if status != http.StatusUnauthorized {
			t.Fatalf("OnAuthFailure status = %d, want 401", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnAuthFailure never fired despite consecutive 401s")
	}
	// The threshold means it must NOT have fired on the very first rejection.
	if requests.Load() < authFailureThreshold {
		t.Fatalf("fired after %d requests, want >= %d", requests.Load(), authFailureThreshold)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunRecoveryFiresOnFlushSuccess(t *testing.T) {
	dbPath := seededStore(t)
	dir := filepath.Dir(dbPath)

	// Reject the first N requests, then accept — emulating a token that gets
	// un-revoked / replaced server-side.
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= authFailureThreshold {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer server.Close()

	recovered := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DBPath:         dbPath,
			StatePath:      filepath.Join(dir, "state.json"),
			CloudURL:       server.URL,
			InstallationID: "ins_test",
			InstallToken:   "rotating-token",
			Interval:       5 * time.Millisecond,
			HTTPClient:     server.Client(),
			Diagnostic:     diagnostic.New(nil, false),
			OnFlushSuccess: func() {
				select {
				case recovered <- struct{}{}:
				default:
				}
			},
		})
	}()

	select {
	case <-recovered:
	case <-time.After(5 * time.Second):
		t.Fatal("OnFlushSuccess never fired after recovery")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
