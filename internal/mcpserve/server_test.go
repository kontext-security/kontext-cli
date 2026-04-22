package mcpserve

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/sidecar"
)

func fakeSidecar(t *testing.T, resp sidecar.EvaluateResult) (string, chan sidecar.EvaluateRequest) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close(); os.Remove(sock) })

	reqs := make(chan sidecar.EvaluateRequest, 8)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req sidecar.EvaluateRequest
				if err := sidecar.ReadMessage(c, &req); err != nil {
					return
				}
				reqs <- req
				_ = sidecar.WriteMessage(c, resp)
			}(conn)
		}
	}()
	return sock, reqs
}

func TestInvokeToolAllowed(t *testing.T) {
	sock, reqs := fakeSidecar(t, sidecar.EvaluateResult{Allowed: true, Reason: ""})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	payload := map[string]any{"provider": "github", "action": "ping"}
	result, err := h.invoke(ctx, payload)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("result parse: %v (raw=%s)", err, result)
	}
	if parsed["status"] != "ok" || parsed["provider"] != "github" {
		t.Fatalf("unexpected result: %v", parsed)
	}

	select {
	case r := <-reqs:
		if r.HookEvent != "PreToolUse" {
			t.Fatalf("expected PreToolUse, got %s", r.HookEvent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pre request")
	}
	select {
	case r := <-reqs:
		if r.HookEvent != "PostToolUse" {
			t.Fatalf("expected PostToolUse, got %s", r.HookEvent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no post request")
	}
}

func TestInvokeToolDenied(t *testing.T) {
	sock, _ := fakeSidecar(t, sidecar.EvaluateResult{Allowed: false, Reason: "policy blocked"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	_, err := h.invoke(ctx, map[string]any{"provider": "github", "action": "ping"})
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !strings.Contains(err.Error(), "policy blocked") {
		t.Fatalf("expected deny reason in error, got %v", err)
	}
}
