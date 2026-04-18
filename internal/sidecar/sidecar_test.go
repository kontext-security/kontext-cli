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
	req := &EvaluateRequest{
		HookEvent:    "PostToolUse",
		ToolName:     "Bash",
		ToolInput:    toolInput,
		ToolResponse: toolResponse,
		ToolUseID:    "toolu_123",
		CWD:          "/tmp/project",
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
	if string(got.ToolInput) != string(toolInput) {
		t.Fatalf("ToolInput = %s, want %s", got.ToolInput, toolInput)
	}
	if string(got.ToolResponse) != string(toolResponse) {
		t.Fatalf("ToolResponse = %s, want %s", got.ToolResponse, toolResponse)
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
