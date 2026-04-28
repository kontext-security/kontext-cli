package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestAcceptLoopReturnsOnListenerError(t *testing.T) {
	t.Parallel()

	ln := &stubListener{acceptErr: errors.New("accept failed")}
	s := &Server{listener: ln}

	done := make(chan struct{})
	go func() {
		s.acceptLoop(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop did not return after listener error")
	}

	if got := ln.accepts; got != 1 {
		t.Fatalf("Accept() calls = %d, want 1", got)
	}
}

func TestDefaultAllowResultOmitsPlaceholderReason(t *testing.T) {
	t.Parallel()

	result := defaultAllowResult()
	if !result.Allowed {
		t.Fatal("defaultAllowResult().Allowed = false, want true")
	}
	if result.Reason != "" {
		t.Fatalf("defaultAllowResult().Reason = %q, want empty", result.Reason)
	}
}

func TestBuildHookEventRequestPreservesTelemetryPayload(t *testing.T) {
	t.Parallel()

	toolInput := json.RawMessage(`{"command":"pwd"}`)
	toolResponse := json.RawMessage(`{"stdout":"/tmp/project"}`)
	isInterrupt := true
	durationMs := int64(42)
	req := &EvaluateRequest{
		HookEvent:      "PostToolUse",
		ToolName:       "Bash",
		ToolInput:      toolInput,
		ToolResponse:   toolResponse,
		ToolUseID:      "toolu_123",
		CWD:            "/tmp/project",
		PermissionMode: "acceptEdits",
		DurationMs:     &durationMs,
		Error:          "failed",
		IsInterrupt:    &isInterrupt,
	}

	got := buildHookEventRequest("session-123", "claude", req)
	if got.SessionId != "session-123" ||
		got.Agent != "claude" ||
		got.HookEvent != req.HookEvent ||
		got.ToolName != req.ToolName ||
		got.ToolUseId != req.ToolUseID ||
		got.Cwd != req.CWD {
		t.Fatalf("buildHookEventRequest() = %+v, want copied metadata", got)
	}
	if got.GetPermissionMode() != req.PermissionMode {
		t.Fatalf("PermissionMode = %q, want %q", got.GetPermissionMode(), req.PermissionMode)
	}
	if got.GetDurationMs() != *req.DurationMs {
		t.Fatalf("DurationMs = %d, want %d", got.GetDurationMs(), *req.DurationMs)
	}
	if got.GetError() != req.Error {
		t.Fatalf("Error = %q, want %q", got.GetError(), req.Error)
	}
	if got.GetIsInterrupt() != *req.IsInterrupt {
		t.Fatalf("IsInterrupt = %t, want %t", got.GetIsInterrupt(), *req.IsInterrupt)
	}
	if string(got.ToolInput) != string(toolInput) {
		t.Fatalf("ToolInput = %s, want %s", got.ToolInput, toolInput)
	}
	if string(got.ToolResponse) != string(toolResponse) {
		t.Fatalf("ToolResponse = %s, want %s", got.ToolResponse, toolResponse)
	}
}

func TestBuildHookEventRequestPreservesExplicitFalseInterrupt(t *testing.T) {
	t.Parallel()

	isInterrupt := false
	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent:   "PostToolUseFailure",
		ToolName:    "Bash",
		ToolUseID:   "toolu_123",
		IsInterrupt: &isInterrupt,
	})

	if got.IsInterrupt == nil {
		t.Fatal("IsInterrupt = nil, want explicit false")
	}
	if got.GetIsInterrupt() {
		t.Fatal("IsInterrupt = true, want false")
	}
}

func TestBuildHookEventRequestPreservesExplicitZeroDuration(t *testing.T) {
	t.Parallel()

	durationMs := int64(0)
	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent:  "PostToolUse",
		ToolName:   "Bash",
		ToolUseID:  "toolu_123",
		DurationMs: &durationMs,
	})

	if got.DurationMs == nil {
		t.Fatal("DurationMs = nil, want explicit zero")
	}
	if got.GetDurationMs() != 0 {
		t.Fatalf("DurationMs = %d, want 0", got.GetDurationMs())
	}
}

type stubListener struct {
	accepts   int
	acceptErr error
}

func (l *stubListener) Accept() (net.Conn, error) {
	l.accepts++
	return nil, l.acceptErr
}

func (l *stubListener) Close() error { return nil }

func (l *stubListener) Addr() net.Addr { return stubAddr("stub") }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }

func (a stubAddr) String() string { return string(a) }
