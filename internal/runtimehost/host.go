package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/modelsnapshot"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
	guardmodels "github.com/kontext-security/kontext-cli/models/guard"
)

const (
	defaultThreshold = 0.5
	defaultHorizon   = 5
)

type Options struct {
	AgentName                 string
	SessionID                 string
	CWD                       string
	DBPath                    string
	ModelPath                 string
	ModelSnapshotDir          string
	SocketPath                string
	DashboardAddr             string
	StartDashboard            bool
	AllowNonLoopbackDashboard bool
	Mode                      string
	Threshold                 float64
	Horizon                   int
	Diagnostic                diagnostic.Logger
	Out                       io.Writer
}

type Host struct {
	SessionID       string
	SessionDir      string
	SocketPath      string
	DBPath          string
	DashboardURL    string
	DashboardErr    error
	ActiveModelPath string
	Mode            guardhookruntime.Mode

	server           *server.Server
	closeStore       func() error
	runtimeService   *localruntime.Service
	dashboardServer  *http.Server
	sessionOpened    bool
	sessionCloseOnce bool
}

func Start(ctx context.Context, opts Options) (*Host, error) {
	if strings.TrimSpace(opts.AgentName) == "" {
		return nil, errors.New("runtime host requires agent name")
	}
	mode, err := ResolveMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	dbPath := strings.TrimSpace(opts.DBPath)
	usingDefaultDBPath := false
	if dbPath == "" {
		dbPath = DefaultDBPath()
		usingDefaultDBPath = true
	}
	if err := ensureRuntimeDataDir(filepath.Dir(dbPath), usingDefaultDBPath); err != nil {
		return nil, fmt.Errorf("create runtime data dir: %w", err)
	}

	scorer, activeModelPath, err := loadScorer(loadScorerOptions{
		DBPath:           dbPath,
		ModelPath:        opts.ModelPath,
		ModelSnapshotDir: opts.ModelSnapshotDir,
		Threshold:        opts.Threshold,
		Horizon:          opts.Horizon,
	})
	if err != nil {
		return nil, err
	}

	localServer, closeStore, err := server.OpenDefaultServer(dbPath, scorer)
	if err != nil {
		return nil, err
	}
	closeStoreOrJoin := func(primary error) error {
		if closeStore == nil {
			return primary
		}
		if err := closeStore(); err != nil {
			return errors.Join(primary, fmt.Errorf("close runtime store: %w", err))
		}
		return primary
	}
	if err := os.Chmod(dbPath, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, closeStoreOrJoin(fmt.Errorf("secure runtime database: %w", err))
	}

	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = NewSessionID()
	}
	if err := validateSessionID(sessionID); err != nil {
		return nil, closeStoreOrJoin(err)
	}
	sessionDir := filepath.Join("/tmp", "kontext", sessionID)
	if err := createSessionDir(sessionDir); err != nil {
		return nil, closeStoreOrJoin(err)
	}
	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		socketPath = filepath.Join(sessionDir, "kontext.sock")
	}

	host := &Host{
		SessionID:       sessionID,
		SessionDir:      sessionDir,
		SocketPath:      socketPath,
		DBPath:          dbPath,
		ActiveModelPath: activeModelPath,
		Mode:            mode,
		server:          localServer,
		closeStore:      closeStore,
	}
	cleanupOrJoin := func(primary error) error {
		if err := host.Close(context.Background()); err != nil {
			return errors.Join(primary, fmt.Errorf("cleanup runtime host: %w", err))
		}
		return primary
	}

	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  socketPath,
		Core:        localServer.RuntimeCore(),
		SessionID:   sessionID,
		AgentName:   opts.AgentName,
		AsyncIngest: true,
		Diagnostic:  opts.Diagnostic,
	})
	if err != nil {
		return nil, cleanupOrJoin(fmt.Errorf("local runtime: %w", err))
	}
	if err := runtimeService.Start(ctx); err != nil {
		return nil, cleanupOrJoin(fmt.Errorf("local runtime start: %w", err))
	}
	host.runtimeService = runtimeService

	cwd := opts.CWD
	if cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, cleanupOrJoin(fmt.Errorf("get working directory: %w", err))
		}
		cwd = wd
	}
	if _, err := localServer.RuntimeCore().OpenSession(ctx, runtimecore.Session{
		ID:         sessionID,
		Agent:      opts.AgentName,
		CWD:        cwd,
		Source:     runtimecore.SessionSourceWrapperOwned,
		ExternalID: sessionID,
	}); err != nil {
		return nil, cleanupOrJoin(fmt.Errorf("open runtime session: %w", err))
	}
	host.sessionOpened = true

	if opts.StartDashboard {
		addr, err := DashboardAddr(opts.DashboardAddr, opts.AllowNonLoopbackDashboard)
		if err != nil {
			return nil, cleanupOrJoin(err)
		}
		dashboardServer, dashboardURL, err := startDashboard(addr, localServer.Handler())
		if err != nil {
			host.DashboardErr = err
			if opts.Out != nil {
				fmt.Fprintf(opts.Out, "Local dashboard unavailable: %v\n", err)
			}
		} else {
			host.dashboardServer = dashboardServer
			host.DashboardURL = dashboardURL
		}
	}

	return host, nil
}

func (h *Host) Close(ctx context.Context) error {
	var errs []error
	if h == nil {
		return nil
	}
	if h.dashboardServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := h.dashboardServer.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			errs = append(errs, err)
		}
		h.dashboardServer = nil
	}
	if h.runtimeService != nil {
		if err := h.runtimeService.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
		h.runtimeService = nil
	}
	if h.sessionOpened && !h.sessionCloseOnce && h.server != nil {
		if err := h.server.RuntimeCore().CloseSession(context.Background(), h.SessionID); err != nil {
			errs = append(errs, err)
		}
		h.sessionCloseOnce = true
	}
	if h.closeStore != nil {
		if err := h.closeStore(); err != nil {
			errs = append(errs, err)
		}
		h.closeStore = nil
	}
	if h.SessionDir != "" {
		if err := os.RemoveAll(h.SessionDir); err != nil {
			errs = append(errs, err)
		}
		h.SessionDir = ""
	}
	return errors.Join(errs...)
}

func ResolveMode(value string) (guardhookruntime.Mode, error) {
	return guardhookruntime.ParseMode(value)
}

func NewSessionID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return hex.EncodeToString(bytes[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)
}

func DefaultDBPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "guard.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".kontext", "guard.db")
	}
	return "kontext-guard.db"
}

func DashboardAddr(value string, allowNonLoopback bool) (string, error) {
	addr := strings.TrimSpace(value)
	if addr == "" {
		addr = server.DefaultAddr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("dashboard address %q must be host:port: %w", addr, err)
	}
	if allowNonLoopback || isLoopbackHost(host) {
		return addr, nil
	}
	return "", fmt.Errorf("dashboard address %q is not loopback; use 127.0.0.1 or localhost", addr)
}

type loadScorerOptions struct {
	DBPath           string
	ModelPath        string
	ModelSnapshotDir string
	Threshold        float64
	Horizon          int
}

func loadScorer(opts loadScorerOptions) (risk.Scorer, string, error) {
	threshold, err := envFloat("KONTEXT_THRESHOLD", opts.Threshold, defaultThreshold)
	if err != nil {
		return nil, "", err
	}
	horizon, err := envInt("KONTEXT_HORIZON", opts.Horizon, defaultHorizon)
	if err != nil {
		return nil, "", err
	}
	snapshotDir := strings.TrimSpace(opts.ModelSnapshotDir)
	if snapshotDir == "" {
		snapshotDir = defaultModelSnapshotDir(opts.DBPath)
	}
	store := modelsnapshot.NewWithValidator(snapshotDir, risk.ValidateMarkovModel)

	modelPath := strings.TrimSpace(opts.ModelPath)
	if modelPath == "" {
		modelPath = strings.TrimSpace(os.Getenv("KONTEXT_MODEL"))
	}
	var snapshot modelsnapshot.Snapshot
	if modelPath == "" {
		snapshot, err = store.ActivateBytes(guardmodels.CodingAgentV0)
	} else {
		snapshot, err = store.ActivateFromFile(modelPath)
	}
	if err != nil {
		return nil, "", fmt.Errorf("activate risk model: %w", err)
	}
	scorer, err := risk.LoadMarkovScorer(snapshot.Path, threshold, horizon)
	if err != nil {
		return nil, "", fmt.Errorf("load risk model: %w", err)
	}
	return scorer, snapshot.Path, nil
}

func startDashboard(addr string, handler http.Handler) (*http.Server, string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("local dashboard listen on %s: %w", addr, err)
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "Local dashboard stopped: %v\n", err)
		}
	}()
	return httpServer, "http://" + ln.Addr().String(), nil
}

func createSessionDir(sessionDir string) error {
	if err := os.MkdirAll(filepath.Dir(sessionDir), 0o700); err != nil {
		return fmt.Errorf("create session parent dir: %w", err)
	}
	if err := os.Mkdir(sessionDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("runtime session directory already exists: %s", sessionDir)
		}
		return fmt.Errorf("create session dir: %w", err)
	}
	return nil
}

func ensureRuntimeDataDir(path string, private bool) error {
	if path == "." || path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if !private {
		return nil
	}
	return os.Chmod(path, 0o700)
}

func defaultModelSnapshotDir(dbPath string) string {
	if dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "models")
	}
	return filepath.Join(".", "models")
}

func envFloat(key string, explicit, fallback float64) (float64, error) {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 0, fmt.Errorf("%s must be a number: %w", key, err)
		}
		return parsed, nil
	}
	if explicit != 0 {
		return explicit, nil
	}
	return fallback, nil
}

func envInt(key string, explicit, fallback int) (int, error) {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return parsed, nil
	}
	if explicit != 0 {
		return explicit, nil
	}
	return fallback, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return errors.New("runtime session ID is required")
	}
	if sessionID != filepath.Base(sessionID) || strings.ContainsAny(sessionID, `/\`) {
		return fmt.Errorf("runtime session ID %q is not a safe path segment", sessionID)
	}
	if sessionID == "." || sessionID == ".." {
		return fmt.Errorf("runtime session ID %q is not a safe path segment", sessionID)
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			continue
		}
		return fmt.Errorf("runtime session ID %q is not a safe path segment", sessionID)
	}
	return nil
}
