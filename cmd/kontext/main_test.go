package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/zalando/go-keyring"
)

func TestLogoutCmdSuccess(t *testing.T) {
	cmd := newLogoutCmd(func() error { return nil })

	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}

	if got, want := stderr.String(), "Logged out successfully.\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestStartCmdHasVerboseFlag(t *testing.T) {
	cmd := startCmd()
	flag := cmd.Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("start command missing --verbose flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--verbose default = %q, want false", flag.DefValue)
	}
}

func TestLogoutCmdAlreadyLoggedOut(t *testing.T) {
	cmd := newLogoutCmd(func() error { return keyring.ErrNotFound })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if got, want := err.Error(), "already logged out"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestLogoutCmdWrapsUnexpectedErrors(t *testing.T) {
	boom := errors.New("boom")
	cmd := newLogoutCmd(func() error { return boom })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("errors.Is(err, boom) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "logout failed: boom") {
		t.Fatalf("error = %q, want wrapped logout failure", err.Error())
	}
}

func TestEvaluateViaSidecarFailsOpenOnMarshalErrors(t *testing.T) {
	t.Parallel()

	socketPath := fmt.Sprintf("/tmp/kontext-test-%d.sock", time.Now().UnixNano())
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	tests := []struct {
		name  string
		event *agent.HookEvent
	}{
		{
			name: "tool input",
			event: &agent.HookEvent{
				ToolInput: map[string]any{"bad": func() {}},
			},
		},
		{
			name: "tool response",
			event: &agent.HookEvent{
				ToolResponse: map[string]any{"bad": func() {}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason, err := evaluateViaSidecar(socketPath, "claude", tt.event)
			if err != nil {
				t.Fatalf("evaluateViaSidecar() error = %v", err)
			}
			if !allowed {
				t.Fatal("evaluateViaSidecar() allowed = false, want true")
			}
			if reason != "sidecar marshal error" {
				t.Fatalf("evaluateViaSidecar() reason = %q, want sidecar marshal error", reason)
			}
		})
	}
}
