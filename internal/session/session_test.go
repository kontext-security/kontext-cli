package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreateAndDisconnect(t *testing.T) {
	var disconnected atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent-sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"id": "sess-123"})
	})
	mux.HandleFunc("POST /api/v1/agent-sessions/sess-123/disconnect", func(w http.ResponseWriter, r *http.Request) {
		disconnected.Store(true)
		w.WriteHeader(201)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	mgr, err := Create(ctx, srv.URL, "tok")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if mgr.ID() != "sess-123" {
		t.Errorf("got ID %q, want %q", mgr.ID(), "sess-123")
	}

	mgr.Disconnect(ctx)
	if !disconnected.Load() {
		t.Error("disconnect was not called")
	}
}

func TestHeartbeat(t *testing.T) {
	var heartbeats atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent-sessions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"id": "sess-456"})
	})
	mux.HandleFunc("POST /api/v1/agent-sessions/sess-456/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		heartbeats.Add(1)
		w.WriteHeader(201)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := Create(ctx, srv.URL, "tok")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mgr.StartHeartbeat(ctx, 50*time.Millisecond)
	time.Sleep(180 * time.Millisecond)
	cancel()

	count := heartbeats.Load()
	if count < 2 {
		t.Errorf("expected at least 2 heartbeats, got %d", count)
	}
}
