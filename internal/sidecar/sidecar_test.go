package sidecar

import (
	"context"
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
