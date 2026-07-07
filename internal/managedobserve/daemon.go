package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

type DaemonOptions struct {
	SocketPath            string
	DBPath                string
	IdleTimeout           time.Duration
	StreamStatePath       string
	StreamInterval        time.Duration
	StreamHTTPClient      *http.Client
	GithubPolicyCachePath string
	GithubPolicyInterval  time.Duration
	GithubPolicyClient    *http.Client
	Diagnostic            diagnostic.Logger
	// FallbackDeploymentVersion is reported to the ledger when no MDM
	// deployment-version marker exists (self-serve brew installs).
	FallbackDeploymentVersion string
	HomebrewUpdater           func(context.Context, managedconfig.LoadedConfig, diagnostic.Logger) <-chan struct{}
}

var (
	managedSettingsDropInPath = claudemanaged.ManagedSettingsDropInPath
	managedSettingsFilePath   = claudemanaged.DefaultManagedSettingsPath()
)

func RunDaemon(ctx context.Context, opts DaemonOptions) error {
	loadedConfig, err := managedconfig.Load()
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return err
		}
		return fmt.Errorf("load managed config: %w", err)
	}
	if expected := strings.TrimSpace(os.Getenv(EnvExpectedConfigScope)); expected != "" &&
		expected != string(loadedConfig.Scope) {
		// An MDM config appeared after this agent was installed (system scope
		// outranks user scope). Park instead of serving the wrong config —
		// exiting would just make launchd KeepAlive restart-loop us.
		fmt.Fprintf(os.Stderr,
			"managed config scope is %q but this agent was installed for %q — parking; run `kontext setup --uninstall` to remove this agent\n",
			loadedConfig.Scope, expected)
		<-ctx.Done()
		return nil
	}
	if err := requireManagedHooksForLegacyCowork(loadedConfig.Config); err != nil {
		return err
	}
	installationState, err := installation.EnsureFile(installationPathForScope(loadedConfig.Scope))
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}

	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = DefaultDBPath()
	}

	_, err = managedconfig.ResolveInstallToken(ctx, loadedConfig.Config.Credentials.InstallTokenRef)
	if err != nil {
		// Leave a breadcrumb: under launchd this exit is otherwise invisible
		// (doctor would only see "daemon: not running" with no cause). A
		// locked login keychain at boot is the typical trigger.
		if breadcrumbErr := WriteStartupError(dbPath, err.Error()); breadcrumbErr != nil {
			opts.Diagnostic.Printf("write startup-error breadcrumb: %v\n", breadcrumbErr)
		}
		return fmt.Errorf("resolve install token: %w", err)
	}
	// Token resolved — clear any stale startup breadcrumb from a prior boot.
	if previous := LoadAuthError(dbPath); previous != nil && previous.Kind == "startup" {
		if err := ClearAuthError(dbPath); err != nil {
			opts.Diagnostic.Printf("clear startup-error breadcrumb: %v\n", err)
		}
	}

	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	if err := EnsureSocketDir(socketPath); err != nil {
		return fmt.Errorf("prepare managed observe socket dir: %w", err)
	}
	if err := cleanupStaleSessions(ctx, dbPath, idleTimeoutOrDefault(opts.IdleTimeout)); err != nil {
		opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
	}

	// The deployment-level mode from managed.json drives every hook edge:
	// observe records would-decisions, enforce returns real denies.
	mode, err := guardhookruntime.ParseMode(loadedConfig.Config.Mode)
	if err != nil {
		return fmt.Errorf("parse managed mode: %w", err)
	}

	policyCachePath := opts.GithubPolicyCachePath
	if policyCachePath == "" {
		policyCachePath = githubpolicy.DefaultCachePathForDB(dbPath)
	}
	policyCache := githubpolicy.NewCache(policyCachePath)
	if err := policyCache.LoadPersisted(); err != nil {
		opts.Diagnostic.Printf("github policy cache load: %v\n", err)
	}

	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:          managedconfig.Agent,
		DBPath:             dbPath,
		SocketPath:         socketPath,
		GithubPolicy:       policyCache,
		EndpointID:         installationState.InstallationID,
		Mode:               mode,
		Diagnostic:         opts.Diagnostic,
		SkipInitialSession: true,
		// Async ingest: non-blocking hooks (PostToolUse, session lifecycle)
		// are acked immediately and written in the background. Synchronous
		// writes queue on the store's single SQLite connection, and under a
		// concurrent subagent burst that queueing blew the hook connection
		// deadline — Claude Code timed the hook out and the event was lost
		// (ENG-474). Decision-gating hooks (PreToolUse, UserPromptSubmit)
		// stay synchronous, and Shutdown drains pending writes.
	})
	if err != nil {
		return err
	}
	defer host.Close(context.Background())

	// Restore the capture mode from the persisted snapshot before the first
	// fetch completes, so an offline restart keeps the org's last-known
	// directive instead of silently reverting to the "summary" default.
	if snapshot, _, ok := policyCache.CurrentSnapshot(); ok {
		host.SetPayloadCaptureMode(payloadcapture.NormalizeMode(snapshot.PayloadCaptureMode))
	}

	policyCtx, stopPolicyRefresh := context.WithCancel(ctx)
	defer stopPolicyRefresh()
	go runGithubPolicy(policyCtx, opts, policyCache, installationState.InstallationID, host.SetPayloadCaptureMode)

	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- runManagedStream(streamCtx, opts, dbPath, installationState.InstallationID)
	}()

	startUpdater := opts.HomebrewUpdater
	if startUpdater == nil {
		startUpdater = startHomebrewUpdater
	}
	upgraded := startUpdater(ctx, loadedConfig, opts.Diagnostic)

	idleTimeout := opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout()
	}
	cleanup := time.NewTicker(cleanupInterval(idleTimeout))
	defer cleanup.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-upgraded:
			if ok {
				return nil
			}
			upgraded = nil
		case err := <-streamErr:
			if err != nil {
				opts.Diagnostic.Printf("managed stream exited: %v\n", err)
				return fmt.Errorf("managed stream failed: %w", err)
			}
			return nil
		case <-cleanup.C:
			if err := cleanupStaleSessions(ctx, dbPath, idleTimeout); err != nil {
				opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
			}
		}
	}
}

func requireManagedHooksForLegacyCowork(cfg managedconfig.Config) error {
	if !cfg.LegacyCoworkEnabled {
		return nil
	}
	foundHooks := false
	for _, path := range []string{managedSettingsDropInPath, managedSettingsFilePath} {
		state, err := managedObserveHooksState(path)
		if err != nil {
			return fmt.Errorf("check Claude Code managed hooks for cowork_enabled: %w", err)
		}
		if state.disabled {
			return fmt.Errorf("cowork_enabled is set but Claude Code hooks are disabled at %s; remove disableAllHooks before starting managed observe", path)
		}
		if state.hasHooks {
			foundHooks = true
		}
	}
	if foundHooks {
		return nil
	}
	return fmt.Errorf("cowork_enabled is set but Claude Code managed hooks are missing at %s or %s; run `kontext setup` or install the managed-settings drop-in before starting managed observe", managedSettingsDropInPath, managedSettingsFilePath)
}

type managedObserveHooksStatus struct {
	disabled bool
	hasHooks bool
}

func managedObserveHooksState(path string) (managedObserveHooksStatus, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return managedObserveHooksStatus{}, nil
	}
	if err != nil {
		return managedObserveHooksStatus{}, err
	}
	return managedObserveHooksStatus{
		disabled: claudemanaged.DisablesAllHooks(data),
		hasHooks: claudemanaged.HasManagedObserveHooks(data),
	}, nil
}

// deploymentVersionWithFallback resolves the version reported with each
// ledger batch: the MDM package marker wins; brew installs have none and
// report the CLI's own version instead. Evaluated per flush so a package
// update under a running daemon is picked up.
func deploymentVersionWithFallback(fallback string) func() string {
	return func() string {
		if v := managedconfig.DeploymentVersion(); v != "" {
			return v
		}
		return fallback
	}
}

// installationPathForScope ties identity scope to config scope: a system
// (MDM) config never reads a user identity and vice versa. The env override
// (KONTEXT_INSTALLATION_STATE, honored by PathFromEnv) always wins, and the
// enterprise default is byte-identical to the pre-self-serve behavior.
func installationPathForScope(scope managedconfig.Scope) string {
	if strings.TrimSpace(os.Getenv(installation.EnvPath)) != "" {
		return installation.PathFromEnv()
	}
	if scope == managedconfig.ScopeUser {
		if path := installation.UserPath(); path != "" {
			return path
		}
	}
	return installation.PathFromEnv()
}

func loadManagedConfig(ctx context.Context) (managedconfig.LoadedConfig, string, error) {
	loadedConfig, err := managedconfig.Load()
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return managedconfig.LoadedConfig{}, "", err
		}
		return managedconfig.LoadedConfig{}, "", fmt.Errorf("load managed config: %w", err)
	}
	installToken, err := managedconfig.ResolveInstallToken(ctx, loadedConfig.Config.Credentials.InstallTokenRef)
	if err != nil {
		return managedconfig.LoadedConfig{}, "", fmt.Errorf("resolve install token: %w", err)
	}
	return loadedConfig, installToken, nil
}

func runGithubPolicy(ctx context.Context, opts DaemonOptions, cache *githubpolicy.Cache, installationID string, applyCaptureMode func(payloadcapture.Mode)) {
	interval := opts.GithubPolicyInterval
	if interval == 0 {
		interval = githubpolicy.DefaultIntervalFromEnv()
	}
	refreshGithubPolicy(ctx, opts, cache, installationID, applyCaptureMode)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshGithubPolicy(ctx, opts, cache, installationID, applyCaptureMode)
		}
	}
}

func refreshGithubPolicy(ctx context.Context, opts DaemonOptions, cache *githubpolicy.Cache, installationID string, applyCaptureMode func(payloadcapture.Mode)) {
	loadedConfig, installToken, err := loadManagedConfig(ctx)
	if err != nil {
		cache.MarkFetchFailed(err)
		opts.Diagnostic.Printf("github policy config reload: %v\n", err)
		return
	}
	snapshot, err := githubpolicy.FetchSnapshot(ctx, opts.GithubPolicyClient, loadedConfig.Config.CloudURL, installToken, installationID)
	if err != nil {
		cache.MarkFetchFailed(err)
		opts.Diagnostic.Printf("github policy refresh: %v\n", err)
		return
	}
	if err := cache.Apply(snapshot, time.Now().UTC()); err != nil {
		opts.Diagnostic.Printf("github policy persist: %v\n", err)
	}
	// Applied from the freshly fetched snapshot, not re-read from the cache:
	// payloadCaptureMode is excluded from the snapshot hash, so the fetched
	// value must win regardless of any hash-based short-circuit.
	if applyCaptureMode != nil {
		applyCaptureMode(payloadcapture.NormalizeMode(snapshot.PayloadCaptureMode))
	}
}

func runManagedStream(ctx context.Context, opts DaemonOptions, dbPath, installationID string) error {
	interval := opts.StreamInterval
	if interval == 0 {
		interval = managedstream.DefaultIntervalFromEnv()
	}
	var consecutiveAuthFailures int
	flush := func() {
		err := flushManagedStream(ctx, opts, dbPath, installationID)
		if err == nil {
			consecutiveAuthFailures = 0
			return
		}
		opts.Diagnostic.Printf("managed stream flush: %v\n", err)
		status, ok := managedstream.AuthFailureStatus(err)
		if !ok {
			consecutiveAuthFailures = 0
			return
		}
		consecutiveAuthFailures++
		if managedstream.ShouldReportAuthFailure(consecutiveAuthFailures) {
			writeStreamAuthFailure(opts, dbPath, status)
		}
	}
	flush()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			flush()
		}
	}
}

func flushManagedStream(ctx context.Context, opts DaemonOptions, dbPath, installationID string) error {
	loadedConfig, installToken, err := loadManagedConfig(ctx)
	if err != nil {
		return fmt.Errorf("managed stream config reload: %w", err)
	}
	if err := managedstream.Flush(ctx, managedstream.Options{
		DBPath:            dbPath,
		StatePath:         opts.StreamStatePath,
		CloudURL:          loadedConfig.Config.CloudURL,
		InstallationID:    installationID,
		InstallToken:      installToken,
		DeviceLabel:       loadedConfig.Config.Device.Label,
		UserEmail:         loadedConfig.Config.Device.UserEmail,
		DeploymentVersion: deploymentVersionWithFallback(opts.FallbackDeploymentVersion),
		HTTPClient:        opts.StreamHTTPClient,
		Diagnostic:        opts.Diagnostic,
		OnFlushSuccess: func() {
			if err := ClearAuthError(dbPath); err != nil {
				opts.Diagnostic.Printf("clear auth-error breadcrumb: %v\n", err)
			}
		},
	}); err != nil {
		return err
	}
	return nil
}

func writeStreamAuthFailure(opts DaemonOptions, dbPath string, status int) {
	// Unconditional stderr (Diagnostic is env-gated and would be silent under
	// launchd) plus a breadcrumb for `kontext doctor`.
	target := "hosted API"
	if loadedConfig, err := managedconfig.Load(); err == nil && strings.TrimSpace(loadedConfig.Config.CloudURL) != "" {
		target = loadedConfig.Config.CloudURL
	}
	fmt.Fprintf(os.Stderr,
		"Kontext install token rejected by %s (HTTP %d). It may have been revoked — run `kontext setup` with a new token from the dashboard.\n",
		target, status)
	if err := WriteAuthError(dbPath, status); err != nil {
		opts.Diagnostic.Printf("write auth-error breadcrumb: %v\n", err)
	}
}

func idleTimeoutOrDefault(idleTimeout time.Duration) time.Duration {
	if idleTimeout == 0 {
		return DefaultIdleTimeout()
	}
	return idleTimeout
}

func cleanupStaleSessions(ctx context.Context, dbPath string, idleTimeout time.Duration) error {
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.CloseStaleDaemonObservedSessions(ctx, time.Now().UTC().Add(-idleTimeout))
}

func cleanupInterval(idleTimeout time.Duration) time.Duration {
	interval := idleTimeout / 2
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}
