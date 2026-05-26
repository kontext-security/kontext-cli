package sidecar

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

// sidecarClient is the backend surface used by the sidecar.
type sidecarClient interface {
	Heartbeat(ctx context.Context, sessionID string) error
	ProcessHookEvent(context.Context, *agentv1.ProcessHookEventRequest) (*backend.ProcessHookEventResult, error)
}

const (
	heartbeatMinInterval = 30 * time.Second
	heartbeatMaxInterval = 5 * time.Minute
	hookEvalTimeout      = 4 * time.Second
)

var trustedGitSearchDirs = []string{
	"/usr/bin",
	"/bin",
	"/usr/local/bin",
	"/opt/homebrew/bin",
	"/opt/local/bin",
}

type heartbeatState struct {
	interval    time.Duration
	lastErr     string
	failedSince time.Time
}

func newHeartbeatState() heartbeatState {
	return heartbeatState{interval: heartbeatMinInterval}
}

func (h *heartbeatState) nextInterval() time.Duration {
	if h.interval == 0 {
		return heartbeatMinInterval
	}
	return h.interval
}

func (h *heartbeatState) record(now time.Time, err error, logf func(string, ...any)) {
	if err != nil {
		errStr := err.Error()
		if h.lastErr != errStr {
			logf("sidecar heartbeat: %v\n", err)
			h.lastErr = errStr
		}
		if h.failedSince.IsZero() {
			h.failedSince = now
		}
		h.interval *= 2
		if h.interval > heartbeatMaxInterval {
			h.interval = heartbeatMaxInterval
		}
		return
	}

	if !h.failedSince.IsZero() {
		elapsed := now.Sub(h.failedSince).Truncate(time.Second)
		logf("sidecar: heartbeat recovered after %s\n", elapsed)
		h.failedSince = time.Time{}
		h.lastErr = ""
	}
	h.interval = heartbeatMinInterval
}

type Server struct {
	socketPath string
	modePath   string
	sessionID  string
	agentName  string
	mu         sync.RWMutex
	accessMode backend.HostedAccessMode
	client     sidecarClient
	core       *runtimecore.Core
	diagnostic diagnostic.Logger
	cancel     context.CancelFunc
}

// New creates a new sidecar server.
func New(sessionDir string, client sidecarClient, sessionID, agentName string, accessMode backend.HostedAccessMode, diagnostics diagnostic.Logger) (*Server, error) {
	s := &Server{
		socketPath: filepath.Join(sessionDir, "kontext.sock"),
		modePath:   filepath.Join(sessionDir, "access-mode"),
		sessionID:  sessionID,
		agentName:  agentName,
		accessMode: accessMode,
		client:     client,
		diagnostic: diagnostics,
	}
	core, err := runtimecore.New(s.hostedRuntime())
	if err != nil {
		return nil, err
	}
	s.core = core
	return s, nil
}

func (s *Server) SocketPath() string { return s.socketPath }

func (s *Server) AccessModePath() string { return s.modePath }

func (s *Server) RuntimeCore() *runtimecore.Core {
	return s.core
}

func (s *Server) RuntimeFailureResult(event hook.Event, err error) hook.Result {
	return s.runtimeFailureResult(event, err)
}

func (s *Server) hostedRuntime() hostedHookRuntime {
	return hostedHookRuntime{
		sessionID: s.sessionID,
		agentName: s.agentName,
		policy: backendPolicyProvider{
			client:    s.client,
			sessionID: s.sessionID,
			agentName: s.agentName,
		},
		diagnostic:        s.diagnostic,
		currentAccessMode: s.currentAccessMode,
		refreshAccessMode: s.refreshAccessMode,
	}
}

func (s *Server) currentAccessMode() backend.HostedAccessMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessMode
}

func (s *Server) refreshAccessMode(mode backend.HostedAccessMode) error {
	if mode == "" {
		return nil
	}
	if err := os.WriteFile(s.modePath, []byte(mode), 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	s.accessMode = mode
	s.mu.Unlock()
	return nil
}

func (s *Server) StartControlPlane(ctx context.Context) error {
	if err := s.writeInitialAccessMode(); err != nil {
		return err
	}
	s.startHeartbeat(ctx)
	return nil
}

func (s *Server) writeInitialAccessMode() error {
	return os.WriteFile(s.modePath, []byte(s.currentAccessMode()), 0o600)
}

func (s *Server) startHeartbeat(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go s.heartbeatLoop(ctx)
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	state := newHeartbeatState()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		timer := time.NewTimer(state.nextInterval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		state.record(time.Now(), s.client.Heartbeat(ctx, s.sessionID), s.diagnostic.Printf)
	}
}

func (s *Server) runtimeFailureResult(event hook.Event, _ error) hook.Result {
	if !event.HookName.CanBlock() {
		return hook.Result{
			Decision: hook.DecisionAllow,
			Reason:   "Kontext hook event could not be ingested.",
		}
	}
	accessMode := s.currentAccessMode()
	if accessMode != backend.HostedAccessModeEnforce {
		return hook.Result{
			Decision: hook.DecisionAllow,
			Reason:   "Kontext hosted access is not enforcing.",
			Mode:     string(accessMode),
		}
	}
	return hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Kontext access policy could not be evaluated.",
	}
}

func buildHookEventRequestFromEvent(event hook.Event) *agentv1.ProcessHookEventRequest {
	hookEvent := &agentv1.ProcessHookEventRequest{
		SessionId: event.SessionID,
		Agent:     event.Agent,
		HookEvent: event.HookName.String(),
		ToolName:  event.ToolName,
		ToolUseId: event.ToolUseID,
		Cwd:       event.CWD,
	}
	if event.PermissionMode != "" {
		hookEvent.PermissionMode = &event.PermissionMode
	}
	if event.DurationMs != nil {
		hookEvent.DurationMs = event.DurationMs
	}
	if event.Error != "" {
		hookEvent.Error = &event.Error
	}
	if event.IsInterrupt != nil {
		hookEvent.IsInterrupt = event.IsInterrupt
	}

	if event.ToolInput != nil {
		input, err := enrichToolInput(event)
		hookEvent.ToolInput = input
		hookEvent.Error = appendHookEventError(hookEvent.Error, err, "tool_input marshal")
	}
	if event.ToolResponse != nil {
		resp, err := marshalMap(event.ToolResponse)
		hookEvent.ToolResponse = resp
		hookEvent.Error = appendHookEventError(hookEvent.Error, err, "tool_response marshal")
	}

	return hookEvent
}

func enrichToolInput(event hook.Event) ([]byte, error) {
	input := cloneMap(event.ToolInput)
	data, err := marshalMap(input)
	// Return best-effort JSON plus the marshal error for upstream reporting.
	if event.HookName != hook.HookPreToolUse || event.ToolName != "Bash" || event.CWD == "" || len(input) == 0 {
		return data, err
	}
	if _, ok := input["command"].(string); !ok {
		if _, ok := input["cmd"].(string); !ok {
			return data, err
		}
	}

	gitContext, ok := collectGitContext(event.CWD)
	if !ok {
		return data, err
	}

	kontext, _ := input["kontext"].(map[string]any)
	if kontext == nil {
		kontext = map[string]any{}
	}
	kontext["git"] = gitContext
	input["kontext"] = kontext

	enriched, enrichedErr := marshalMap(input)
	if err == nil {
		err = enrichedErr
	} else if enrichedErr != nil {
		err = joinErrors(err, enrichedErr)
	}
	return enriched, err
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func appendHookEventError(existing *string, err error, context string) *string {
	if err == nil {
		return existing
	}
	msg := "sidecar: " + context + " failed: " + err.Error()
	if existing == nil || *existing == "" {
		return &msg
	}
	combined := *existing + "\n" + msg
	return &combined
}

func joinErrors(a, b error) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return fmt.Errorf("%v; %v", a, b)
}

func collectGitContext(cwd string) (map[string]any, bool) {
	gitPath, ok := trustedGitPath()
	if !ok {
		return nil, false
	}

	root := strings.TrimSpace(runGit(gitPath, cwd, "rev-parse", "--show-toplevel"))
	if root == "" {
		return nil, false
	}

	git := map[string]any{
		"worktreeRoot": root,
	}
	if branch := strings.TrimSpace(runGit(gitPath, cwd, "rev-parse", "--abbrev-ref", "HEAD")); branch != "" && branch != "HEAD" {
		git["branch"] = branch
	}

	remoteNames := strings.Fields(runGit(gitPath, cwd, "remote"))
	remotes := map[string]string{}
	for _, name := range remoteNames {
		remoteURL := strings.TrimSpace(runGit(gitPath, cwd, "remote", "get-url", name))
		if remoteURL == "" {
			continue
		}
		remotes[name] = sanitizeGitRemoteURL(remoteURL)
	}
	if len(remotes) > 0 {
		git["remotes"] = remotes
	}

	return git, true
}

func trustedGitPath() (string, bool) {
	for _, dir := range trustedGitSearchDirs {
		path := filepath.Join(dir, "git")
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return path, true
	}
	return "", false
}

func runGit(gitPath, cwd string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, gitPath, append([]string{"-C", cwd}, args...)...)
	cmd.Env = []string{
		"GIT_TERMINAL_PROMPT=0",
		"PATH=" + filepath.Dir(gitPath),
		"HOME=" + os.Getenv("HOME"),
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func sanitizeGitRemoteURL(remoteURL string) string {
	if strings.Contains(remoteURL, "://") {
		parsed, err := url.Parse(remoteURL)
		if err != nil || parsed.Host == "" {
			return remoteURL
		}
		if parsed.User != nil {
			parsed.User = nil
		}
		return parsed.String()
	}
	return remoteURL
}
