package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cli/browser"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

const (
	defaultBaseURL = "http://" + server.DefaultAddr
)

// Run executes the Kontext command line.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}
	switch args[0] {
	case "start", "daemon":
		return runDaemon(ctx, args[1:], stdout)
	case "stop":
		fmt.Fprintln(stdout, "Stop the foreground `kontext guard start` process with Ctrl-C.")
		return nil
	case "status":
		return runStatus(ctx, args[1:], stdout)
	case "dashboard":
		return runDashboard(args[1:], stdout)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout)
	case "hooks":
		return runHooks(args[1:], stdout)
	case "traces":
		return runTraces(ctx, args[1:], stdout)
	case "judge":
		return runJudge(ctx, args[1:], stdout)
	case "smoke-test":
		return runSmokeTest(ctx, args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Kontext Guard")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "commands:")
	fmt.Fprintln(out, "  start                         Run the local daemon on 127.0.0.1:4765")
	fmt.Fprintln(out, "  stop                          Print stop instructions")
	fmt.Fprintln(out, "  status                        Print local dashboard counters")
	fmt.Fprintln(out, "  dashboard                     Print dashboard URL")
	fmt.Fprintln(out, "  doctor                        Check local daemon health")
	fmt.Fprintln(out, "  hooks install claude-code     Install Claude Code hooks")
	fmt.Fprintln(out, "  hooks uninstall claude-code   Remove Claude Code hooks")
	fmt.Fprintln(out, "  traces inspect                Inspect local trace summary")
	fmt.Fprintln(out, "  judge eval                    Evaluate local judge fixtures")
}

func runDaemon(ctx context.Context, args []string, out io.Writer) error {
	defaultJudgeTimeout, err := envDuration("KONTEXT_JUDGE_TIMEOUT", judge.DefaultTimeout)
	if err != nil {
		return err
	}
	defaultJudgeManaged, err := envBool("KONTEXT_JUDGE_MANAGED", false)
	if err != nil {
		return err
	}
	defaultJudgePort, err := envInt("KONTEXT_JUDGE_PORT", judge.DefaultLlamaServerPort)
	if err != nil {
		return err
	}
	defaultJudgeStartupTimeout, err := envDuration("KONTEXT_JUDGE_STARTUP_TIMEOUT", judge.DefaultLlamaServerStartupTimeout)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", envString("KONTEXT_ADDR", server.DefaultAddr), "listen address")
	dbPath := fs.String("db", envString("KONTEXT_DB", defaultDBPath()), "SQLite database path")
	skipHookInstall := fs.Bool("skip-hook-install", false, "skip Claude Code hook install")
	noOpen := fs.Bool("no-open", false, "do not open the local dashboard")
	socketPath := fs.String("socket", defaultGuardSocketPath(), "Unix socket path for local hook runtime")
	judgeURL := fs.String("judge-url", envString("KONTEXT_JUDGE_URL", ""), "OpenAI-compatible local judge base URL, for example http://127.0.0.1:8080")
	judgeModel := fs.String("judge-model", envString("KONTEXT_JUDGE_MODEL", ""), "local judge model name; with --judge-managed this may be a local GGUF path")
	judgeTimeout := fs.Duration("judge-timeout", defaultJudgeTimeout, "local judge timeout")
	judgeManaged := fs.Bool("judge-managed", defaultJudgeManaged, "start and health-check a managed llama-server child process")
	judgeServerBin := fs.String("judge-server-bin", envString("KONTEXT_JUDGE_SERVER_BIN", judge.DefaultLlamaServerBinary), "llama-server binary path")
	judgeModelPath := fs.String("judge-model-path", envString("KONTEXT_JUDGE_MODEL_PATH", ""), "local GGUF model path for managed llama-server")
	judgeHFRepo := fs.String("judge-hf-repo", envString("KONTEXT_JUDGE_HF_REPO", ""), "Hugging Face GGUF repo to cache for managed llama-server")
	judgeHFFile := fs.String("judge-hf-file", envString("KONTEXT_JUDGE_HF_FILE", ""), "Hugging Face GGUF filename to cache for managed llama-server")
	judgeHFRevision := fs.String("judge-hf-revision", envString("KONTEXT_JUDGE_HF_REVISION", ""), "Hugging Face revision, branch, or tag to cache for managed llama-server")
	judgeCacheDir := fs.String("judge-cache-dir", envString("KONTEXT_JUDGE_CACHE_DIR", ""), "directory for cached GGUF judge models")
	judgePort := fs.Int("judge-port", defaultJudgePort, "managed llama-server port")
	judgeStartupTimeout := fs.Duration("judge-startup-timeout", defaultJudgeStartupTimeout, "managed llama-server startup timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*skipHookInstall {
		if err := verifyClaudeCode(); err != nil {
			return err
		}
		if err := installClaudeHooks(out, *socketPath); err != nil {
			return err
		}
	}
	localJudge, closeJudge, judgeStatus, err := configureLocalJudge(ctx, localJudgeConfig{
		URL:            *judgeURL,
		Model:          *judgeModel,
		Timeout:        *judgeTimeout,
		Managed:        *judgeManaged,
		ServerBin:      *judgeServerBin,
		ModelPath:      *judgeModelPath,
		HFRepo:         *judgeHFRepo,
		HFFile:         *judgeHFFile,
		HFRevision:     *judgeHFRevision,
		CacheDir:       resolvedJudgeCacheDir(*judgeCacheDir, *dbPath),
		Port:           *judgePort,
		StartupTimeout: *judgeStartupTimeout,
	})
	if err != nil {
		return err
	}
	defer closeJudge()
	localServer, closeStore, err := server.OpenDefaultServerWithOptions(*dbPath, server.Options{
		Judge: localJudge,
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = closeStore()
	}()
	if err := ensureGuardSocketDir(*socketPath); err != nil {
		return err
	}
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  *socketPath,
		Core:        localServer.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(out, diagnostic.EnabledFromEnv()),
	})
	if err != nil {
		return err
	}
	if err := runtimeService.Start(context.Background()); err != nil {
		return fmt.Errorf("local runtime start: %w", err)
	}
	defer runtimeService.Stop()
	fmt.Fprintf(out, "Kontext Guard local daemon listening on http://%s\n", *addr)
	fmt.Fprintf(out, "Hook runtime: unix://%s\n", *socketPath)
	fmt.Fprintln(out, "Mode: observe (Claude Code runs normally; decisions are recorded as would allow / would ask / would deny).")
	fmt.Fprintf(out, "Dashboard: http://%s\n", *addr)
	if localJudge != nil {
		fmt.Fprintf(out, "Local judge: %s\n", judgeStatus)
	} else {
		fmt.Fprintln(out, "Local judge: disabled")
	}
	if !*noOpen {
		_ = browser.OpenURL("http://" + *addr)
	}
	return localServer.ListenAndServe(*addr)
}

type localJudgeConfig struct {
	URL            string
	Model          string
	Timeout        time.Duration
	Managed        bool
	ServerBin      string
	ModelPath      string
	HFRepo         string
	HFFile         string
	HFRevision     string
	CacheDir       string
	Port           int
	StartupTimeout time.Duration
}

func configureLocalJudge(ctx context.Context, cfg localJudgeConfig) (judge.Judge, func(), string, error) {
	closeFn := func() {}
	if cfg.Managed {
		return configureManagedJudge(ctx, cfg)
	}
	if strings.TrimSpace(cfg.URL) == "" && strings.TrimSpace(cfg.Model) == "" {
		return nil, closeFn, "", nil
	}
	if strings.TrimSpace(cfg.URL) == "" || strings.TrimSpace(cfg.Model) == "" {
		return nil, closeFn, "", fmt.Errorf("--judge-url and --judge-model must be set together")
	}
	if err := validateLocalJudgeURL(cfg.URL); err != nil {
		return nil, closeFn, "", err
	}
	localJudge, err := judge.NewOpenAICompatibleJudge(judge.HTTPOptions{
		BaseURL: cfg.URL,
		Model:   cfg.Model,
		Timeout: cfg.Timeout,
	})
	if err != nil {
		return nil, closeFn, "", err
	}
	return localJudge, closeFn, fmt.Sprintf("%s at %s", cfg.Model, cfg.URL), nil
}

func configureManagedJudge(ctx context.Context, cfg localJudgeConfig) (judge.Judge, func(), string, error) {
	closeFn := func() {}
	modelPath := strings.TrimSpace(cfg.ModelPath)
	modelName := strings.TrimSpace(cfg.Model)
	if modelPath == "" && looksLikeGGUFPath(modelName) {
		modelPath = modelName
		modelName = ""
	}
	hfRepo := strings.TrimSpace(cfg.HFRepo)
	hfFile := strings.TrimSpace(cfg.HFFile)
	if modelPath == "" && hfRepo == "" {
		hfRepo = judge.DefaultLlamaServerHFRepo
		if hfFile == "" {
			hfFile = judge.DefaultLlamaServerHFFile
		}
	}
	if modelName == "" {
		modelName = managedJudgeModelName(modelPath, hfRepo, hfFile)
	}
	host, port, baseURL, err := managedJudgeListenConfig(cfg.URL, cfg.Port)
	if err != nil {
		return nil, closeFn, "", err
	}
	server, err := judge.StartLlamaServer(ctx, judge.LlamaServerOptions{
		BinaryPath:     cfg.ServerBin,
		ModelPath:      modelPath,
		HFRepo:         hfRepo,
		HFFile:         hfFile,
		HFRevision:     cfg.HFRevision,
		CacheDir:       cfg.CacheDir,
		Host:           host,
		Port:           port,
		StartupTimeout: cfg.StartupTimeout,
	})
	if err != nil {
		unavailable := judge.UnavailableJudge{
			Runtime: judge.DefaultLlamaServerRuntime,
			Model:   modelName,
			Kind:    judge.FailureUnavailable,
			Err:     err,
		}
		return unavailable, closeFn, fmt.Sprintf("%s unavailable (%v)", modelName, err), nil
	}
	closeFn = func() {
		_ = server.Stop()
	}
	localJudge, err := judge.NewOpenAICompatibleJudge(judge.HTTPOptions{
		BaseURL: baseURL,
		Model:   modelName,
		Runtime: judge.DefaultLlamaServerRuntime,
		Timeout: cfg.Timeout,
	})
	if err != nil {
		closeFn()
		return nil, func() {}, "", err
	}
	return localJudge, closeFn, fmt.Sprintf("%s at %s (%s)", modelName, baseURL, judge.DefaultLlamaServerRuntime), nil
}

func managedJudgeListenConfig(rawURL string, port int) (string, int, string, error) {
	if port <= 0 {
		port = judge.DefaultLlamaServerPort
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return judge.DefaultLlamaServerHost, port, managedJudgeBaseURL(judge.DefaultLlamaServerHost, port), nil
	}
	if err := validateLocalJudgeURL(rawURL); err != nil {
		return "", 0, "", err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, "", fmt.Errorf("parse judge URL: %w", err)
	}
	if parsed.Scheme != "http" {
		return "", 0, "", fmt.Errorf("managed judge URL must use http")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, "", fmt.Errorf("managed judge URL must include host")
	}
	if parsed.Port() != "" {
		parsedPort, err := strconv.Atoi(parsed.Port())
		if err != nil || parsedPort <= 0 {
			return "", 0, "", fmt.Errorf("managed judge URL has invalid port %q", parsed.Port())
		}
		port = parsedPort
	}
	return host, port, managedJudgeBaseURL(host, port), nil
}

func managedJudgeBaseURL(host string, port int) string {
	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}).String()
}

func looksLikeGGUFPath(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasSuffix(strings.ToLower(value), ".gguf") || strings.Contains(value, string(filepath.Separator))
}

func managedJudgeModelName(modelPath, hfRepo, hfFile string) string {
	if strings.TrimSpace(hfRepo) != "" {
		return strings.TrimSpace(hfRepo)
	}
	if strings.TrimSpace(modelPath) != "" {
		return filepath.Base(modelPath)
	}
	if strings.TrimSpace(hfFile) != "" {
		return strings.TrimSpace(hfFile)
	}
	return "local-judge"
}

func resolvedJudgeCacheDir(cacheDir, dbPath string) string {
	if strings.TrimSpace(cacheDir) != "" {
		return cacheDir
	}
	return defaultJudgeCacheDir(dbPath)
}

func verifyClaudeCode() error {
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("Claude Code was not found on PATH; install Claude Code or run with --skip-hook-install")
	}
	return nil
}

func runStatus(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	summary, err := fetchSummary(ctx, *baseURL)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Kontext Guard active")
	fmt.Fprintf(out, "%d critical\n", summary.Critical)
	fmt.Fprintf(out, "%d warnings\n", summary.Warnings)
	fmt.Fprintf(out, "%d actions\n", summary.Actions)
	fmt.Fprintf(out, "Dashboard: %s\n", *baseURL)
	return nil
}

func runDashboard(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	noOpen := fs.Bool("no-open", false, "print URL without opening a browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n", *baseURL)
	if !*noOpen {
		_ = browser.OpenURL(*baseURL)
	}
	return nil
}

func fetchSummary(ctx context.Context, baseURL string) (sqlite.Summary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/summary", nil)
	if err != nil {
		return sqlite.Summary{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sqlite.Summary{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sqlite.Summary{}, fmt.Errorf("daemon returned %s", resp.Status)
	}
	var summary sqlite.Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return sqlite.Summary{}, err
	}
	return summary, nil
}

func runDoctor(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	PrintHookStatus(out)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("local daemon is not reachable at %s: %w", *baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local daemon health returned %s", resp.Status)
	}
	fmt.Fprintf(out, "Kontext Guard daemon healthy at %s\n", *baseURL)
	return nil
}

func PrintHookStatus(out io.Writer) {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		fmt.Fprintf(out, "Claude Code hooks: unavailable (%v)\n", err)
		return
	}
	fmt.Fprintf(out, "Claude Code settings: %s\n", settingsPath)
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok || len(hooks) == 0 {
		fmt.Fprintln(out, "Claude Code hooks: none installed")
		return
	}
	hosted := false
	guard := false
	for _, raw := range hooks {
		for _, command := range hookCommands(raw) {
			switch {
			case isGuardHookCommand(command):
				guard = true
				fmt.Fprintf(out, "Claude Code Guard hook: %s\n", command)
			case strings.Contains(command, "kontext hook"):
				hosted = true
				fmt.Fprintf(out, "Claude Code hosted hook: %s\n", command)
			}
		}
	}
	if guard && hosted {
		fmt.Fprintln(out, "Claude Code hook mode: conflict (hosted and Guard hooks are both installed)")
		return
	}
	if guard {
		fmt.Fprintln(out, "Claude Code hook mode: local Guard")
		return
	}
	if hosted {
		fmt.Fprintln(out, "Claude Code hook mode: hosted")
		return
	}
	fmt.Fprintln(out, "Claude Code hook mode: no Kontext hook detected")
}

func hookCommands(raw any) []string {
	groups, ok := raw.([]any)
	if !ok {
		return nil
	}
	var commands []string
	for _, group := range groups {
		groupMap, ok := group.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := groupMap["hooks"].([]any)
		if !ok {
			continue
		}
		for _, hook := range hooks {
			hookMap, ok := hook.(map[string]any)
			if !ok {
				continue
			}
			if command, ok := hookMap["command"].(string); ok {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func runHooks(args []string, out io.Writer) error {
	if len(args) < 2 || args[1] != "claude-code" {
		return fmt.Errorf("usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code")
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("hooks install claude-code", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		socketPath := fs.String("socket", defaultGuardSocketPath(), "Unix socket path for local hook runtime")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return installClaudeHooks(out, *socketPath)
	case "uninstall":
		if len(args) != 2 {
			return fmt.Errorf("usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code")
		}
		return uninstallClaudeHooks(out)
	default:
		return fmt.Errorf("usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code")
	}
}

func installClaudeHooks(out io.Writer, socketPath string) error {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		return err
	}
	if err := backupFile(settingsPath, "kontext-guard"); err != nil {
		return err
	}
	hookCommand := installedHookCommand(socketPath)
	settings["hooks"] = mergeHooks(settings["hooks"], hookCommand)
	if err := writeJSONFile(settingsPath, settings); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed Kontext Guard Claude Code hooks into %s\n", settingsPath)
	fmt.Fprintf(out, "Hook command: %s\n", hookCommand)
	fmt.Fprintln(out, "Default mode is observe. Set KONTEXT_MODE=enforce later to block ask/deny decisions.")
	return nil
}

func uninstallClaudeHooks(out io.Writer) error {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		return err
	}
	if err := backupFile(settingsPath, "kontext-guard"); err != nil {
		return err
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		fmt.Fprintf(out, "No Claude Code hooks found in %s\n", settingsPath)
		return nil
	}
	for hookName, raw := range hooks {
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(list))
		for _, entry := range list {
			if !isGuardHookEntry(entry) {
				filtered = append(filtered, entry)
			}
		}
		hooks[hookName] = filtered
	}
	if err := writeJSONFile(settingsPath, settings); err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed Kontext Guard Claude Code hooks from %s\n", settingsPath)
	return nil
}

func readClaudeSettings() (string, map[string]any, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil, err
	}
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		return "", nil, err
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	settings := map[string]any{}
	raw, err := os.ReadFile(settingsPath)
	if err == nil {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return "", nil, fmt.Errorf("parse Claude settings: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	return settingsPath, settings, nil
}

func backupFile(path, label string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	backupPath := fmt.Sprintf("%s.%s-backup-%s", path, label, time.Now().UTC().Format("20060102T150405Z"))
	input, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, input, 0o644)
}

func writeJSONFile(path string, value any) error {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(path, bytes, 0o644)
}

func mergeHooks(raw any, hookCommand string) map[string]any {
	hooks, ok := raw.(map[string]any)
	if !ok {
		hooks = map[string]any{}
	}
	for _, hookName := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		var list []any
		if existing, ok := hooks[hookName].([]any); ok {
			for _, entry := range existing {
				if !isGuardHookEntry(entry) {
					list = append(list, entry)
				}
			}
		}
		if len(list) == 0 {
			delete(hooks, hookName)
			continue
		}
		hooks[hookName] = list
	}
	for _, hookName := range []string{"PreToolUse", "PostToolUse"} {
		var list []any
		if existing, ok := hooks[hookName].([]any); ok {
			list = append(list, existing...)
		}
		list = append(list, map[string]any{
			"matcher": "*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": hookCommand,
				},
			},
		})
		hooks[hookName] = list
	}
	return hooks
}

func isGuardHookEntry(entry any) bool {
	return isGuardHookCommand(fmt.Sprintf("%v", entry))
}

func isGuardHookCommand(command string) bool {
	normalized := strings.ReplaceAll(command, "'", "")
	return strings.Contains(normalized, "kontext guard hook claude-code") ||
		(strings.Contains(normalized, "kontext hook --agent claude") && strings.Contains(normalized, "--mode"))
}

func runSmokeTest(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("smoke-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "kontext-guard-smoke-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	localServer, err := server.NewServer(store)
	if err != nil {
		return err
	}
	socketPath := filepath.Join(dir, "kontext.sock")
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  socketPath,
		Core:        localServer.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(io.Discard, false),
	})
	if err != nil {
		return err
	}
	if err := runtimeService.Start(ctx); err != nil {
		return err
	}
	defer runtimeService.Stop()
	client := localruntime.NewClient(socketPath)
	cases := []struct {
		name string
		ev   hook.Event
		want hook.Decision
	}{
		{"safe read", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}}, hook.DecisionAllow},
		{"env read", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}}, hook.DecisionDeny},
		{"cat env", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "cat .env"}}, hook.DecisionDeny},
		{"provider token", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'"}}, hook.DecisionDeny},
		{"drop database", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}}, hook.DecisionDeny},
	}
	for _, item := range cases {
		result, err := client.Process(ctx, item.ev)
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		if result.Decision != item.want {
			return fmt.Errorf("%s: decision=%s want=%s", item.name, result.Decision, item.want)
		}
		fmt.Fprintf(out, "ok %-16s -> %s\n", item.name, result.Decision)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	if summary.Actions != 5 || summary.Warnings != 0 || summary.Critical != 4 {
		return fmt.Errorf("summary=%+v, want actions=5 warnings=0 critical=4", summary)
	}
	fmt.Fprintf(out, "summary critical=%d warnings=%d actions=%d\n", summary.Critical, summary.Warnings, summary.Actions)
	return nil
}

func runTraces(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kontext guard traces inspect")
	}
	switch args[0] {
	case "inspect":
		return runStatus(ctx, args[1:], out)
	default:
		return fmt.Errorf("usage: kontext guard traces inspect")
	}
}

func runJudge(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kontext guard judge eval")
	}
	switch args[0] {
	case "eval":
		return runJudgeEval(ctx, args[1:], out)
	default:
		return fmt.Errorf("usage: kontext guard judge eval")
	}
}

func runJudgeEval(ctx context.Context, args []string, out io.Writer) error {
	defaultJudgeTimeout, err := envDuration("KONTEXT_JUDGE_TIMEOUT", 10*time.Second)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("judge eval", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	judgeURL := fs.String("judge-url", envString("KONTEXT_JUDGE_URL", ""), "OpenAI-compatible local judge base URL")
	judgeModel := fs.String("judge-model", envString("KONTEXT_JUDGE_MODEL", ""), "local judge model name")
	judgeTimeout := fs.Duration("judge-timeout", defaultJudgeTimeout, "local judge timeout")
	fixturesPath := fs.String("fixtures", "internal/guard/judge/testdata/launch-v0.jsonl", "judge evaluation JSONL fixtures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*judgeURL) == "" || strings.TrimSpace(*judgeModel) == "" {
		return fmt.Errorf("--judge-url and --judge-model are required")
	}
	if err := validateLocalJudgeURL(*judgeURL); err != nil {
		return err
	}
	localJudge, err := judge.NewOpenAICompatibleJudge(judge.HTTPOptions{
		BaseURL: *judgeURL,
		Model:   *judgeModel,
		Timeout: *judgeTimeout,
	})
	if err != nil {
		return err
	}
	fixtures, err := readJudgeEvalFixtures(*fixturesPath)
	if err != nil {
		return err
	}
	total := 0
	passed := 0
	for _, fixture := range fixtures {
		if !fixture.JudgeExpected.ShouldCallJudge {
			continue
		}
		total++
		result, err := localJudge.Decide(ctx, judge.InputFromFixture(fixture))
		if err != nil {
			fmt.Fprintf(out, "FAIL %s: judge error: %v\n", fixture.ID, err)
			continue
		}
		if failures := judge.CompareFixtureOutput(result.Output, fixture.JudgeExpected); len(failures) > 0 {
			fmt.Fprintf(out, "FAIL %s: %s reason=%q\n", fixture.ID, strings.Join(failures, "; "), result.Output.Reason)
			continue
		}
		passed++
		fmt.Fprintf(out, "PASS %s: %s %s\n", fixture.ID, result.Output.Decision, result.Output.RiskLevel)
	}
	fmt.Fprintf(out, "summary passed=%d failed=%d total=%d\n", passed, total-passed, total)
	if passed != total {
		return fmt.Errorf("judge eval failed %d of %d fixtures", total-passed, total)
	}
	return nil
}

func readJudgeEvalFixtures(path string) ([]judge.Fixture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fixtures, err := judge.ReadFixtures(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return fixtures, nil
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func envBool(key string, fallback bool) (bool, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("%s must be a boolean: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be a duration: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func validateLocalJudgeURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse judge URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("judge URL must use http or https")
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return nil
	default:
		return fmt.Errorf("judge URL must point to localhost")
	}
}

func defaultDBPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "guard.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".kontext", "guard.db")
	}
	return "kontext-guard.db"
}

func defaultJudgeCacheDir(dbPath string) string {
	if dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "judge-models")
	}
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "judge")
	}
	return filepath.Join(".", "judge-models")
}

func selfPath() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	return "kontext"
}

func installedHookCommand(socketPath string) string {
	if command := os.Getenv("KONTEXT_GUARD_HOOK_COMMAND"); strings.TrimSpace(command) != "" {
		return command
	}
	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultGuardSocketPath()
	}
	path := selfPath()
	if strings.Contains(path, "go-build") {
		if cwd, err := os.Getwd(); err == nil {
			if _, statErr := os.Stat(filepath.Join(cwd, "cmd", "kontext")); statErr == nil {
				return fmt.Sprintf("cd %s && %s", shellQuote(cwd), installedHookInvocation("go run ./cmd/kontext", socketPath))
			}
		}
	}
	return installedHookInvocation(shellQuote(path), socketPath)
}

func installedHookInvocation(launcher, socketPath string) string {
	return fmt.Sprintf("%s hook --agent claude --mode \"${KONTEXT_MODE:-observe}\" --socket %s", launcher, shellQuote(socketPath))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
