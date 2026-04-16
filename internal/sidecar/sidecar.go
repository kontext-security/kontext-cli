package sidecar

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
)

type Server struct {
	socketPath string
	listener   net.Listener
	sessionID  string
	agentName  string
	client     *backend.Client
	cancel     context.CancelFunc
}

func New(sessionDir string, client *backend.Client, sessionID, agentName string) (*Server, error) {
	return &Server{
		socketPath: filepath.Join(sessionDir, "kontext.sock"),
		sessionID:  sessionID,
		agentName:  agentName,
		client:     client,
	}, nil
}

func (s *Server) SocketPath() string { return s.socketPath }

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
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					log.Printf("sidecar: accept temporary error: %v", err)
					continue
				}
				log.Printf("sidecar: accept: %v", err)
				return
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("sidecar: deadline: %v", err)
		return
	}

	var req EvaluateRequest
	if err := ReadMessage(conn, &req); err != nil {
		log.Printf("sidecar: read: %v", err)
		return
	}

	result := EvaluateResult{Type: "result", Allowed: true, Reason: "allowed"}
	if err := WriteMessage(conn, result); err != nil {
		log.Printf("sidecar: write: %v", err)
		return
	}

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
		log.Printf("sidecar: ingest: %v", err)
	}
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.client.Heartbeat(ctx, s.sessionID); err != nil {
				log.Printf("sidecar: heartbeat: %v", err)
			}
		}
	}
}
