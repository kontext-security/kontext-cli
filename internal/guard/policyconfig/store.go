package policyconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/policy"
)

type clockFunc func() time.Time

type Option func(*Store)

type Store struct {
	root   string
	clock  clockFunc
	write  func(path string, data []byte, perm os.FileMode) error
	locker func(context.Context) (func(), error)

	mu      sync.RWMutex
	current Snapshot
}

func WithClock(clock clockFunc) Option {
	return func(s *Store) {
		if clock != nil {
			s.clock = clock
		}
	}
}

func withWriter(write func(path string, data []byte, perm os.FileMode) error) Option {
	return func(s *Store) {
		if write != nil {
			s.write = write
		}
	}
}

func withLocker(locker func(context.Context) (func(), error)) Option {
	return func(s *Store) {
		if locker != nil {
			s.locker = locker
		}
	}
}

func Open(dir string, opts ...Option) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("policy config directory is required")
	}
	store := &Store{
		root:  dir,
		clock: func() time.Time { return time.Now().UTC() },
		write: writeFileAtomic,
	}
	store.locker = store.lockFile
	for _, opt := range opts {
		opt(store)
	}
	return store, nil
}

func (s *Store) Load(ctx context.Context) (Snapshot, error) {
	unlockStore, err := s.lockStore(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer unlockStore()
	unlockFile, err := s.locker(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer unlockFile()

	active, err := s.readConfig(s.activePath())
	if err == nil {
		data, err := encodeConfig(active)
		if err != nil {
			return Snapshot{}, err
		}
		if err := s.write(s.lastKnownGoodPath(), data, fileMode); err != nil {
			return Snapshot{}, err
		}
		snapshot, err := s.snapshot(active, SourceActiveFile, StatusOK)
		if err != nil {
			return Snapshot{}, err
		}
		s.current = cloneSnapshot(snapshot)
		return cloneSnapshot(snapshot), nil
	}
	activeMissing := errors.Is(err, os.ErrNotExist)
	activeInvalid := isValidationError(err)
	if !activeMissing && !activeInvalid {
		return Snapshot{}, err
	}

	lkg, lkgErr := s.readConfig(s.lastKnownGoodPath())
	if lkgErr == nil {
		if activeMissing {
			return s.activateRecovered(lkg, SourceLastKnownGood, StatusDefaultedMissing)
		}
		return s.activateRecovered(lkg, SourceLastKnownGood, StatusRecoveredLKG)
	}
	if lkgErr != nil && !errors.Is(lkgErr, os.ErrNotExist) && !isValidationError(lkgErr) {
		return Snapshot{}, lkgErr
	}
	if activeMissing {
		return s.activateRecovered(DefaultConfig(), SourceDefault, StatusDefaultedMissing)
	}
	return s.activateRecovered(DefaultConfig(), SourceDefault, StatusDefaultedInvalid)
}

func (s *Store) Current() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.current)
}

func (s *Store) Activate(ctx context.Context, candidate Config) (Snapshot, error) {
	unlockStore, err := s.lockStore(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer unlockStore()
	unlockFile, err := s.locker(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer unlockFile()

	data, err := encodeConfig(candidate)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := s.snapshot(candidate, SourceActiveFile, StatusOK)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.write(s.lastKnownGoodPath(), data, fileMode); err != nil {
		return Snapshot{}, err
	}
	if err := s.write(s.activePath(), data, fileMode); err != nil {
		return Snapshot{}, err
	}
	s.current = cloneSnapshot(snapshot)
	return cloneSnapshot(snapshot), nil
}

func (s *Store) ActivateProfile(ctx context.Context, profile policy.Profile) (Snapshot, error) {
	cfg := DefaultConfig()
	cfg.Profile = profile
	return s.Activate(ctx, cfg)
}

func (s *Store) activateRecovered(cfg Config, source Source, status Status) (Snapshot, error) {
	data, err := encodeConfig(cfg)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := s.snapshot(cfg, source, status)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.write(s.lastKnownGoodPath(), data, fileMode); err != nil {
		return Snapshot{}, err
	}
	if err := s.write(s.activePath(), data, fileMode); err != nil {
		return Snapshot{}, err
	}
	s.current = cloneSnapshot(snapshot)
	return cloneSnapshot(snapshot), nil
}

func (s *Store) readConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return decodeConfig(data)
}

func (s *Store) snapshot(cfg Config, source Source, status Status) (Snapshot, error) {
	cfg = cloneConfig(cfg)
	pack := policy.DefaultRulePack()
	digest, err := configDigest(cfg)
	if err != nil {
		return Snapshot{}, err
	}
	now := s.clock()
	return Snapshot{
		Config:          cfg,
		ConfigDigest:    digest,
		ActivationID:    digest[:12],
		Source:          source,
		Status:          status,
		LoadedAt:        now,
		PolicyVersion:   cfg.Version,
		RulePack:        cfg.RulePack,
		RulePackVersion: pack.Version,
	}, nil
}

func (s *Store) activePath() string {
	return filepath.Join(s.root, "guard", "policy", "active.json")
}

func (s *Store) lastKnownGoodPath() string {
	return filepath.Join(s.root, "guard", "policy", "last-known-good.json")
}

func (s *Store) lockPath() string {
	return filepath.Join(s.root, "guard", "policy", ".lock")
}

func (s *Store) lockStore(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		if s.mu.TryLock() {
			return s.mu.Unlock, nil
		}
		if err := waitForLockRetry(ctx); err != nil {
			return nil, err
		}
	}
}

func (s *Store) lockFile(ctx context.Context) (func(), error) {
	path := s.lockPath()
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, err
	}
	return lockFileAt(ctx, path)
}

func waitForLockRetry(ctx context.Context) error {
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func configDigest(cfg Config) (string, error) {
	data, err := encodeConfig(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func isValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
