package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/kontext-dev/kontext-cli/internal/agent"
	"github.com/kontext-dev/kontext-cli/internal/policy"
)

// Server is the local sidecar that hook handlers communicate with.
type Server struct {
	socketPath string
	listener   net.Listener
	mu         sync.Mutex
	engine     *policy.Engine
	auditor    *Auditor
}

// New creates a new sidecar server with a Unix socket in the given directory.
func New(sessionDir string) (*Server, error) {
	socketPath := filepath.Join(sessionDir, "kontext.sock")
	return &Server{socketPath: socketPath}, nil
}

// SetEngine sets the policy engine for evaluating hook events.
func (s *Server) SetEngine(engine *policy.Engine) {
	s.engine = engine
}

// SetAuditor sets the auditor for recording MCP events.
func (s *Server) SetAuditor(auditor *Auditor) {
	s.auditor = auditor
}

// SocketPath returns the Unix socket path for hook handlers to connect to.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Start begins listening on the Unix socket.
func (s *Server) Start(ctx context.Context) error {
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("sidecar: listen: %w", err)
	}
	s.listener = ln

	go s.serve(ctx)
	return nil
}

// Stop shuts down the sidecar and cleans up the socket.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
}

func (s *Server) serve(ctx context.Context) {
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

// decision is the JSON response written back to the hook binary.
type decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func (s *Server) handleConn(_ context.Context, conn net.Conn) {
	defer conn.Close()

	data, err := ReadMessage(conn)
	if err != nil {
		s.writeDecision(conn, false, "sidecar: read error")
		return
	}

	var event agent.HookEvent
	if err := json.Unmarshal(data, &event); err != nil {
		s.writeDecision(conn, false, "sidecar: decode error")
		return
	}

	if s.engine == nil {
		s.writeDecision(conn, false, "sidecar: no policy engine configured")
		return
	}

	allowed, reason := s.engine.Evaluate(event.ToolName, event.ToolUseID)

	if s.auditor != nil {
		s.auditor.Record(event.ToolName, event.ToolInput, allowed, reason, event.SessionID)
	}

	s.writeDecision(conn, allowed, reason)
}

func (s *Server) writeDecision(conn net.Conn, allowed bool, reason string) {
	resp, _ := json.Marshal(decision{Allowed: allowed, Reason: reason})
	WriteMessage(conn, resp)
}
