package managedobserve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

func TestLifecycleMissingSocketKickstartsAndFailsOpenObserve(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")
	kickstarts := 0
	lifecycle := Lifecycle{
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			kickstarts++
			return nil
		},
	}

	result := lifecycle.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})

	if kickstarts != 1 {
		t.Fatalf("kickstarts = %d, want 1", kickstarts)
	}
	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
}

func TestLifecyclePollsAfterKickstartWithinDeadline(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-delayed-test-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ready := make(chan struct{})
	done := make(chan struct{})

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			go func() {
				time.Sleep(50 * time.Millisecond)
				ln, err := net.Listen("unix", socketPath)
				if err != nil {
					close(done)
					return
				}
				defer ln.Close()
				defer close(done)
				close(ready)
				for i := 0; i < 2; i++ {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					if i == 0 {
						_ = conn.Close()
						continue
					}
					var req localruntime.EvaluateRequest
					if err := localruntime.ReadMessage(conn, &req); err == nil {
						_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{
							Decision: "deny",
							Allowed:  false,
							Reason:   "delayed policy",
						})
					}
					_ = conn.Close()
				}
			}()
			return nil
		},
	}

	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if result.Reason != "Kontext observe mode: would deny; delayed policy" {
		t.Fatalf("reason = %q, want delayed daemon result", result.Reason)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("delayed daemon did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delayed daemon did not receive request")
	}
}

func TestLifecycleKickstartFailureIsDiagnosedAndFailsOpen(t *testing.T) {
	var output bytes.Buffer
	lifecycle := Lifecycle{
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			return errors.New("launchd refused")
		},
		Diagnostic: diagnostic.New(&output, true),
	}

	result := lifecycle.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})

	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if !strings.Contains(output.String(), "managed observe kickstart: launchd refused") {
		t.Fatalf("diagnostic output = %q, want kickstart failure", output.String())
	}
}

func TestLifecycleHealthySocketDoesNotKickstart(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-test-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req localruntime.EvaluateRequest
		if err := localruntime.ReadMessage(conn, &req); err != nil {
			return
		}
		_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{
			Decision: "deny",
			Allowed:  false,
			Reason:   "policy deny",
		})
	}()

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			t.Fatal("kickstart should not be called")
			return nil
		},
	}
	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if result.Reason != "Kontext observe mode: would deny; policy deny" {
		t.Fatalf("reason = %q, want observe deny reason", result.Reason)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
}

func TestActiveRequiresValidManagedConfig(t *testing.T) {
	t.Setenv("KONTEXT_MANAGED_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	if Active() {
		t.Fatal("Active() = true for missing config")
	}

	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(`{
  "version": "managed-install-v1",
  "organization_id": "org_123",
  "cloud_url": "https://app.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}
}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("KONTEXT_MANAGED_CONFIG", path)
	if !Active() {
		t.Fatal("Active() = false for valid config")
	}
}
