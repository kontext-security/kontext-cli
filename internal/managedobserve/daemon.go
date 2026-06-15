package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/kontext-security/kontext-cli/internal/coworkobserve"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
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
}

func RunDaemon(ctx context.Context, opts DaemonOptions) error {
	runtimeConfig, err := loadManagedRuntimeConfig(ctx)
	if err != nil {
		return err
	}
	installationState, err := installation.Ensure()
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}

	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	if err := EnsureSocketDir(socketPath); err != nil {
		return fmt.Errorf("prepare managed observe socket dir: %w", err)
	}
	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = DefaultDBPath()
	}
	if err := cleanupStaleSessions(ctx, dbPath, idleTimeoutOrDefault(opts.IdleTimeout)); err != nil {
		opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
	}

	// The deployment-level mode from managed.json drives every hook edge:
	// observe records would-decisions, enforce returns real denies.
	mode, err := guardhookruntime.ParseMode(runtimeConfig.Mode)
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
		Mode:               mode,
		Diagnostic:         opts.Diagnostic,
		SkipInitialSession: true,
		DisableAsyncIngest: true,
	})
	if err != nil {
		return err
	}
	defer host.Close(context.Background())

	policyCtx, stopPolicyRefresh := context.WithCancel(ctx)
	defer stopPolicyRefresh()
	go runGithubPolicyRefresh(policyCtx, opts, policyCache)

	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- runManagedStream(streamCtx, opts, dbPath, installationState.InstallationID)
	}()

	// Cowork observation runs alongside Claude Code in the same daemon, replaying
	// in-VM Cowork tool events into the same localruntime socket as agent "cowork".
	// Enabled via managed.json (cowork_enabled) or the env var override.
	if runtimeConfig.CoworkEnabled || coworkobserve.Enabled() {
		go coworkobserve.Run(ctx, coworkobserve.Options{
			SocketPath: socketPath,
			StatePath:  filepath.Join(filepath.Dir(dbPath), "cowork-spool-offsets.json"),
			Mode:       mode,
			Diagnostic: opts.Diagnostic,
		})
	}

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

type managedRuntimeConfig struct {
	CloudURL       string
	OrganizationID string
	InstallToken   string
	DeviceLabel    string
	Mode           string
	CoworkEnabled  bool
}

func loadManagedRuntimeConfig(ctx context.Context) (managedRuntimeConfig, error) {
	loadedConfig, err := managedconfig.Load()
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return managedRuntimeConfig{}, err
		}
		return managedRuntimeConfig{}, fmt.Errorf("load managed config: %w", err)
	}
	installToken, err := managedconfig.ResolveInstallToken(ctx, loadedConfig.Config.Credentials.InstallTokenRef)
	if err != nil {
		return managedRuntimeConfig{}, fmt.Errorf("resolve install token: %w", err)
	}
	return managedRuntimeConfig{
		CloudURL:       loadedConfig.Config.CloudURL,
		OrganizationID: loadedConfig.Config.OrganizationID,
		InstallToken:   installToken,
		DeviceLabel:    loadedConfig.Config.Device.Label,
		Mode:           loadedConfig.Config.Mode,
		CoworkEnabled:  loadedConfig.Config.CoworkEnabled,
	}, nil
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

func runGithubPolicyRefresh(ctx context.Context, opts DaemonOptions, cache *githubpolicy.Cache) {
	interval := opts.GithubPolicyInterval
	if interval == 0 {
		interval = githubpolicy.DefaultIntervalFromEnv()
	}
	refreshGithubPolicy(ctx, opts, cache)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshGithubPolicy(ctx, opts, cache)
		}
	}
}

func refreshGithubPolicy(ctx context.Context, opts DaemonOptions, cache *githubpolicy.Cache) {
	runtimeConfig, err := loadManagedRuntimeConfig(ctx)
	if err != nil {
		cache.MarkFetchFailed(err)
		opts.Diagnostic.Printf("github policy config reload: %v\n", err)
		return
	}
	snapshot, err := githubpolicy.FetchSnapshot(ctx, opts.GithubPolicyClient, runtimeConfig.CloudURL, runtimeConfig.InstallToken)
	if err != nil {
		cache.MarkFetchFailed(err)
		opts.Diagnostic.Printf("github policy refresh: %v\n", err)
		return
	}
	if err := cache.Apply(snapshot, time.Now().UTC()); err != nil {
		opts.Diagnostic.Printf("github policy persist: %v\n", err)
	}
}

func runManagedStream(ctx context.Context, opts DaemonOptions, dbPath, installationID string) error {
	interval := opts.StreamInterval
	if interval == 0 {
		interval = managedstream.DefaultIntervalFromEnv()
	}
	flushManagedStream(ctx, opts, dbPath, installationID)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			flushManagedStream(ctx, opts, dbPath, installationID)
		}
	}
}

func flushManagedStream(ctx context.Context, opts DaemonOptions, dbPath, installationID string) {
	streamOpts, err := managedStreamOptions(ctx, opts, dbPath, installationID)
	if err != nil {
		opts.Diagnostic.Printf("managed stream config reload: %v\n", err)
		return
	}
	if err := managedstream.Flush(ctx, streamOpts); err != nil {
		opts.Diagnostic.Printf("managed stream flush: %v\n", err)
	}
}

func managedStreamOptions(ctx context.Context, opts DaemonOptions, dbPath, installationID string) (managedstream.Options, error) {
	runtimeConfig, err := loadManagedRuntimeConfig(ctx)
	if err != nil {
		return managedstream.Options{}, err
	}
	return managedstream.Options{
		DBPath:            dbPath,
		StatePath:         opts.StreamStatePath,
		CloudURL:          runtimeConfig.CloudURL,
		OrganizationID:    runtimeConfig.OrganizationID,
		InstallationID:    installationID,
		InstallToken:      runtimeConfig.InstallToken,
		DeviceLabel:       runtimeConfig.DeviceLabel,
		DeploymentVersion: managedconfig.DeploymentVersion,
		HTTPClient:        opts.StreamHTTPClient,
		Diagnostic:        opts.Diagnostic,
	}, nil
}

func cleanupInterval(idleTimeout time.Duration) time.Duration {
	interval := idleTimeout / 2
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}
