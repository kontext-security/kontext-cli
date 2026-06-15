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
	loadedConfig, err := managedconfig.Load()
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return err
		}
		return fmt.Errorf("load managed config: %w", err)
	}
	installationState, err := installation.Ensure()
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}
	installToken, err := managedconfig.ResolveInstallToken(ctx, loadedConfig.Config.Credentials.InstallTokenRef)
	if err != nil {
		return fmt.Errorf("resolve install token: %w", err)
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
	go githubpolicy.Run(policyCtx, githubpolicy.RunOptions{
		Cache:        policyCache,
		CloudURL:     loadedConfig.Config.CloudURL,
		InstallToken: installToken,
		Interval:     opts.GithubPolicyInterval,
		HTTPClient:   opts.GithubPolicyClient,
		Diagnostic:   opts.Diagnostic,
	})

	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- managedstream.Run(streamCtx, managedstream.Options{
			DBPath:            dbPath,
			StatePath:         opts.StreamStatePath,
			CloudURL:          loadedConfig.Config.CloudURL,
			OrganizationID:    loadedConfig.Config.OrganizationID,
			InstallationID:    installationState.InstallationID,
			InstallToken:      installToken,
			DeviceLabel:       loadedConfig.Config.Device.Label,
			DeploymentVersion: managedconfig.DeploymentVersion,
			Interval:          opts.StreamInterval,
			HTTPClient:        opts.StreamHTTPClient,
			Diagnostic:        opts.Diagnostic,
		})
	}()

	// Cowork observation runs alongside Claude Code in the same daemon, replaying
	// in-VM Cowork tool events into the same localruntime socket as agent "cowork".
	// Enabled via managed.json (cowork_enabled) or the env var override.
	if loadedConfig.Config.CoworkEnabled || coworkobserve.Enabled() {
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
