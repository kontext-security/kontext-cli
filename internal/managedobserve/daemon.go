package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

type DaemonOptions struct {
	SocketPath  string
	DBPath      string
	IdleTimeout time.Duration
	Diagnostic  diagnostic.Logger
}

func RunDaemon(ctx context.Context, opts DaemonOptions) error {
	if _, err := managedconfig.Load(); err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return err
		}
		return fmt.Errorf("load managed config: %w", err)
	}
	if _, err := installation.Ensure(); err != nil {
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

	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:          managedconfig.Agent,
		DBPath:             dbPath,
		SocketPath:         socketPath,
		Mode:               guardhookruntime.ModeObserve,
		Diagnostic:         opts.Diagnostic,
		SkipInitialSession: true,
		DisableAsyncIngest: true,
	})
	if err != nil {
		return err
	}
	defer host.Close(context.Background())

	idleTimeout := opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout()
	}
	cleanup := time.NewTicker(cleanupInterval(idleTimeout))
	defer cleanup.Stop()
	if err := cleanupStaleSessions(ctx, dbPath, idleTimeout); err != nil {
		opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-cleanup.C:
			if err := cleanupStaleSessions(ctx, dbPath, idleTimeout); err != nil {
				opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
			}
		}
	}
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
