package localruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

const hookConnDeadline = 10 * time.Second

type Service struct {
	socketPath  string
	listener    net.Listener
	core        *runtimecore.Core
	sessionID   string
	agentName   string
	asyncIngest bool
	onFailure   func(hook.Event, error) hook.Result
	diagnostic  diagnostic.Logger
	cancel      context.CancelFunc
	serveDone   chan struct{}
	wg          sync.WaitGroup
}

type Options struct {
	SocketPath  string
	Core        *runtimecore.Core
	SessionID   string
	AgentName   string
	AsyncIngest bool
	OnFailure   func(hook.Event, error) hook.Result
	Diagnostic  diagnostic.Logger
}

func NewService(opts Options) (*Service, error) {
	if opts.SocketPath == "" {
		return nil, errors.New("local runtime service requires socket path")
	}
	if opts.Core == nil {
		return nil, errors.New("local runtime service requires runtime core")
	}
	return &Service{
		socketPath:  opts.SocketPath,
		core:        opts.Core,
		sessionID:   opts.SessionID,
		agentName:   opts.AgentName,
		asyncIngest: opts.AsyncIngest,
		onFailure:   opts.OnFailure,
		diagnostic:  opts.Diagnostic,
	}, nil
}

func (s *Service) SocketPath() string { return s.socketPath }

func (s *Service) Start(ctx context.Context) error {
	if err := removeStaleSocket(s.socketPath); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	s.listener = ln

	ctx, s.cancel = context.WithCancel(ctx)
	s.serveDone = make(chan struct{})
	go s.acceptLoop(ctx, ln, s.serveDone)
	return nil
}

func (s *Service) Stop() {
	_ = s.Shutdown(context.Background())
}

func (s *Service) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	removeRuntimeSocket(s.socketPath)

	if s.serveDone != nil {
		select {
		case <-s.serveDone:
		case <-ctx.Done():
			if s.cancel != nil {
				s.cancel()
			}
			return ctx.Err()
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		if s.cancel != nil {
			s.cancel()
		}
		return nil
	case <-ctx.Done():
		if s.cancel != nil {
			s.cancel()
		}
		return ctx.Err()
	}
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect socket path: %w", err)
	}
	if info.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("socket path %q exists and is not a Unix socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func removeRuntimeSocket(path string) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Type() != os.ModeSocket {
		return
	}
	_ = os.Remove(path)
}

func (s *Service) acceptLoop(ctx context.Context, listener net.Listener, done chan<- struct{}) {
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				s.diagnostic.Printf("local runtime accept: %v\n", err)
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Service) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(hookConnDeadline)); err != nil {
		s.diagnostic.Printf("local runtime deadline: %v\n", err)
		return
	}

	var req EvaluateRequest
	if err := ReadMessage(conn, &req); err != nil {
		s.diagnostic.Printf("local runtime read: %v\n", err)
		return
	}

	result := s.process(ctx, &req)
	if err := WriteMessage(conn, result); err != nil {
		s.diagnostic.Printf("local runtime write: %v\n", err)
		return
	}

	if s.asyncIngest && req.HookEvent != hook.HookPreToolUse.String() {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.ingestEvent(ctx, &req)
		}()
	}
}

func (s *Service) ingestEvent(ctx context.Context, req *EvaluateRequest) {
	event, err := EventFromEvaluateRequest(s.sessionID, s.agentName, req)
	if err != nil {
		s.diagnostic.Printf("local runtime ingest decode: %v\n", err)
		return
	}
	if _, err := s.core.IngestEvent(ctx, event); err != nil {
		s.diagnostic.Printf("local runtime ingest: %v\n", err)
	}
}

func (s *Service) process(ctx context.Context, req *EvaluateRequest) EvaluateResult {
	event, err := EventFromEvaluateRequest(s.sessionID, s.agentName, req)
	if err != nil {
		s.diagnostic.Printf("local runtime decode: %v\n", err)
		return EvaluateResultFromResult(decodeFailureResult(req))
	}
	if s.asyncIngest && !event.HookName.CanBlock() {
		return EvaluateResultFromResult(hook.Result{Decision: hook.DecisionAllow})
	}
	result, err := s.core.ProcessHook(ctx, event)
	if err != nil {
		s.diagnostic.Printf("local runtime process: %v\n", err)
		if s.onFailure != nil {
			return EvaluateResultFromResult(s.onFailure(event, err))
		}
		return EvaluateResultFromResult(processFailureResult(event))
	}
	return EvaluateResultFromResult(result)
}

func decodeFailureResult(req *EvaluateRequest) hook.Result {
	if req != nil {
		hookName, ok := normalizeHookName(req.HookEvent)
		if ok && !hookName.CanBlock() {
			return hook.Result{
				Decision: hook.DecisionAllow,
				Reason:   "Kontext hook event could not be decoded.",
			}
		}
	}
	return hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Kontext hook event could not be decoded.",
	}
}

func processFailureResult(event hook.Event) hook.Result {
	if !event.HookName.CanBlock() {
		return hook.Result{
			Decision: hook.DecisionAllow,
			Reason:   "Kontext hook event could not be ingested.",
		}
	}
	return hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Kontext access policy could not be evaluated.",
	}
}
