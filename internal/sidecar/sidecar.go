// Package sidecar implements the local session server.
// Hook handlers connect over a Unix socket. The sidecar relays events
// to the Kontext backend via ConnectRPC and keeps the session alive.
package sidecar

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentv1 "github.com/kontext-dev/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-dev/kontext-cli/internal/auth"
	"github.com/kontext-dev/kontext-cli/internal/backend"
)

const defaultHeartbeatInterval = 30 * time.Second

// backendClient is the subset of *backend.Client that the sidecar uses.
// It exists so tests can substitute a fake implementation.
type backendClient interface {
	Heartbeat(ctx context.Context, sessionID string) error
	IngestEvent(ctx context.Context, req *agentv1.ProcessHookEventRequest) error
}

// Server is the local sidecar that hook handlers communicate with.
type Server struct {
	socketPath        string
	listener          net.Listener
	sessionID         string
	agentName         string
	client            backendClient
	cancel            context.CancelFunc
	heartbeatInterval time.Duration
	authFailed        sync.Once
}

// New creates a new sidecar server.
func New(sessionDir string, client *backend.Client, sessionID, agentName string) (*Server, error) {
	return &Server{
		socketPath:        filepath.Join(sessionDir, "kontext.sock"),
		sessionID:         sessionID,
		agentName:         agentName,
		client:            client,
		heartbeatInterval: defaultHeartbeatInterval,
	}, nil
}

// SocketPath returns the Unix socket path.
func (s *Server) SocketPath() string { return s.socketPath }

// Start begins listening and processing hook events.
func (s *Server) Start(ctx context.Context) error {
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	s.listener = ln

	ctx, s.cancel = context.WithCancel(ctx)
	go s.acceptLoop(ctx)
	go s.heartbeatLoop(ctx)

	return nil
}

// Stop shuts down the sidecar.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req EvaluateRequest
	if err := ReadMessage(conn, &req); err != nil {
		log.Printf("sidecar: read: %v", err)
		return
	}

	// Always allow for now — policy evaluation is a future phase
	result := EvaluateResult{Type: "result", Allowed: true, Reason: "allowed"}
	if err := WriteMessage(conn, result); err != nil {
		log.Printf("sidecar: write: %v", err)
		return
	}

	// Ingest event asynchronously via ConnectRPC
	go s.ingestEvent(ctx, &req)
}

func (s *Server) ingestEvent(ctx context.Context, req *EvaluateRequest) {
	hookEvent := &agentv1.ProcessHookEventRequest{
		SessionId: s.sessionID,
		Agent:     s.agentName,
		HookEvent: req.HookEvent,
		ToolName:  req.ToolName,
		ToolUseId: req.ToolUseID,
		Cwd:       req.CWD,
	}

	if len(req.ToolInput) > 0 {
		hookEvent.ToolInput = req.ToolInput
	}
	if len(req.ToolResponse) > 0 {
		hookEvent.ToolResponse = req.ToolResponse
	}

	if err := s.client.IngestEvent(ctx, hookEvent); err != nil {
		if s.handleAuthFailure(err) {
			return
		}
		log.Printf("sidecar: ingest: %v", err)
	}
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(s.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.client.Heartbeat(ctx, s.sessionID); err != nil {
				if s.handleAuthFailure(err) {
					return
				}
				log.Printf("sidecar: heartbeat: %v", err)
			}
		}
	}
}

// handleAuthFailure checks whether err represents a permanent authentication
// failure (refresh token revoked or expired beyond recovery). On the first
// such error, it prints a user-facing re-auth message and cancels the
// sidecar's context to stop both heartbeat and event-ingestion loops. The
// agent child process continues running — the user can finish their work
// without telemetry and re-authenticate next session.
//
// Returns true if the error was a permanent auth failure (caller should
// exit its loop without additional logging).
func (s *Server) handleAuthFailure(err error) bool {
	if !errors.Is(err, auth.ErrInvalidGrant) {
		return false
	}
	s.authFailed.Do(func() {
		fmt.Fprintln(os.Stderr, "✗ Your session has expired. Please run `kontext login` to continue receiving telemetry.")
		if s.cancel != nil {
			s.cancel()
		}
	})
	return true
}
