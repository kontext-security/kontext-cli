package policyconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/policy"
)

func TestLoadMissingConfigMaterializesDefault(t *testing.T) {
	store := newTestStore(t)

	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Source != SourceDefault || snapshot.Status != StatusDefaultedMissing {
		t.Fatalf("snapshot source/status = %s/%s", snapshot.Source, snapshot.Status)
	}
	if snapshot.Config.Profile != policy.ProfileBalanced {
		t.Fatalf("profile = %q, want balanced", snapshot.Config.Profile)
	}
	assertFileExists(t, filepath.Join(store.root, "guard", "policy", "active.json"))
	assertFileExists(t, filepath.Join(store.root, "guard", "policy", "last-known-good.json"))
	if got := store.Current(); got.ConfigDigest != snapshot.ConfigDigest {
		t.Fatalf("Current() digest = %q, want %q", got.ConfigDigest, snapshot.ConfigDigest)
	}
}

func TestLoadMissingActiveRecoversFromLastKnownGood(t *testing.T) {
	store := newTestStore(t)
	activated, err := store.ActivateProfile(context.Background(), policy.ProfileStrict)
	if err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}
	if err := os.Remove(store.activePath()); err != nil {
		t.Fatalf("Remove(active) error = %v", err)
	}

	reopened := newStoreAt(t, store.root)
	snapshot, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Source != SourceLastKnownGood || snapshot.Status != StatusDefaultedMissing {
		t.Fatalf("source/status = %s/%s, want lkg/defaulted_missing", snapshot.Source, snapshot.Status)
	}
	if snapshot.Config.Profile != policy.ProfileStrict {
		t.Fatalf("profile = %q, want strict", snapshot.Config.Profile)
	}
	if snapshot.ConfigDigest != activated.ConfigDigest {
		t.Fatalf("digest = %q, want %q", snapshot.ConfigDigest, activated.ConfigDigest)
	}
	if cfg := readConfigFile(t, reopened.activePath()); cfg.Profile != policy.ProfileStrict {
		t.Fatalf("active profile = %q, want strict", cfg.Profile)
	}
	if cfg := readConfigFile(t, reopened.lastKnownGoodPath()); cfg.Profile != policy.ProfileStrict {
		t.Fatalf("LKG profile = %q, want strict", cfg.Profile)
	}
}

func TestLoadValidActiveRefreshesLastKnownGood(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.ActivateProfile(context.Background(), policy.ProfileBalanced); err != nil {
		t.Fatalf("ActivateProfile(balanced) error = %v", err)
	}

	strict := DefaultConfig()
	strict.Profile = policy.ProfileStrict
	strictData, err := encodeConfig(strict)
	if err != nil {
		t.Fatalf("encodeConfig(strict) error = %v", err)
	}
	if err := os.WriteFile(store.activePath(), strictData, fileMode); err != nil {
		t.Fatalf("WriteFile(active) error = %v", err)
	}

	reopened := newStoreAt(t, store.root)
	snapshot, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Config.Profile != policy.ProfileStrict {
		t.Fatalf("profile = %q, want strict", snapshot.Config.Profile)
	}
	if cfg := readConfigFile(t, reopened.lastKnownGoodPath()); cfg.Profile != policy.ProfileStrict {
		t.Fatalf("LKG profile = %q, want strict", cfg.Profile)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	store := newTestStore(t)
	writeActive(t, store, `{
  "version": "guard-policy-v1",
  "profile": "balanced",
  "rulePack": "guard-default",
  "nonBypassableRules": true,
  "rules": []
}`)

	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Status != StatusDefaultedInvalid {
		t.Fatalf("status = %s, want %s", snapshot.Status, StatusDefaultedInvalid)
	}
}

func TestActivateInvalidLeavesCurrentAndDiskUnchanged(t *testing.T) {
	store := newTestStore(t)
	initial, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	before := readActive(t, store)

	cfg := DefaultConfig()
	cfg.Profile = "unknown"
	_, err = store.Activate(context.Background(), cfg)
	var validationErr ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Activate() error = %T %v, want ValidationError", err, err)
	}
	if got := store.Current(); got.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("Current() changed after invalid activate")
	}
	if after := readActive(t, store); after != before {
		t.Fatalf("active file changed after invalid activate")
	}
}

func TestActivateFailureWritingLKGLeavesActiveAndMemoryUnchanged(t *testing.T) {
	root := t.TempDir()
	store := newStoreAt(t, root)
	initial, err := store.ActivateProfile(context.Background(), policy.ProfileBalanced)
	if err != nil {
		t.Fatalf("ActivateProfile(initial) error = %v", err)
	}
	beforeActive := readActive(t, store)

	writeErr := errors.New("write lkg failed")
	failingStore := newStoreAt(t, root, withWriter(func(path string, data []byte, perm os.FileMode) error {
		if filepath.Base(path) == "last-known-good.json" {
			return writeErr
		}
		return writeFileAtomic(path, data, perm)
	}))
	seedCurrent(failingStore, initial)

	_, err = failingStore.ActivateProfile(context.Background(), policy.ProfileStrict)
	if !errors.Is(err, writeErr) {
		t.Fatalf("ActivateProfile() error = %v, want %v", err, writeErr)
	}
	if got := readActive(t, failingStore); got != beforeActive {
		t.Fatalf("active file changed after LKG write failure")
	}
	if got := failingStore.Current(); got.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("Current() changed after LKG write failure")
	}
	reopened := newStoreAt(t, root)
	loaded, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatalf("reopened Load() error = %v", err)
	}
	if loaded.Config.Profile != policy.ProfileBalanced {
		t.Fatalf("reopened profile = %q, want balanced", loaded.Config.Profile)
	}
}

func TestActivateFailureWritingActiveLeavesNewConfigRecoverableFromLKG(t *testing.T) {
	root := t.TempDir()
	store := newStoreAt(t, root)
	initial, err := store.ActivateProfile(context.Background(), policy.ProfileBalanced)
	if err != nil {
		t.Fatalf("ActivateProfile(initial) error = %v", err)
	}
	beforeActive := readActive(t, store)

	writeErr := errors.New("write active failed")
	failingStore := newStoreAt(t, root, withWriter(func(path string, data []byte, perm os.FileMode) error {
		if filepath.Base(path) == "active.json" {
			return writeErr
		}
		return writeFileAtomic(path, data, perm)
	}))
	seedCurrent(failingStore, initial)

	_, err = failingStore.ActivateProfile(context.Background(), policy.ProfileStrict)
	if !errors.Is(err, writeErr) {
		t.Fatalf("ActivateProfile() error = %v, want %v", err, writeErr)
	}
	if got := readActive(t, failingStore); got != beforeActive {
		t.Fatalf("active file changed after active write failure")
	}
	if got := failingStore.Current(); got.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("Current() changed after active write failure")
	}

	writeActive(t, failingStore, `{"version":`)
	reopened := newStoreAt(t, root)
	loaded, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatalf("reopened Load() error = %v", err)
	}
	if loaded.Config.Profile != policy.ProfileStrict {
		t.Fatalf("reopened profile = %q, want strict from LKG recovery", loaded.Config.Profile)
	}
	if loaded.Status != StatusRecoveredLKG {
		t.Fatalf("reopened status = %s, want %s", loaded.Status, StatusRecoveredLKG)
	}
}

func TestConcurrentActivateSerializesDiskWrites(t *testing.T) {
	root := t.TempDir()
	firstLKGWritten := make(chan struct{})
	secondStarted := make(chan struct{})
	allowFirstActive := make(chan struct{})
	interleaved := make(chan string, 1)

	var writeMu sync.Mutex
	lkgWrites := 0
	firstPendingActive := false
	store := newStoreAt(t, root, withWriter(func(path string, data []byte, perm os.FileMode) error {
		profile := "unknown"
		if strings.Contains(string(data), `"profile": "strict"`) {
			profile = "strict"
		} else if strings.Contains(string(data), `"profile": "relaxed"`) {
			profile = "relaxed"
		}

		writeMu.Lock()
		isFirstLKG := filepath.Base(path) == "last-known-good.json" && lkgWrites == 0
		if firstPendingActive && profile == "relaxed" {
			select {
			case interleaved <- filepath.Base(path) + ":" + profile:
			default:
			}
		}
		if filepath.Base(path) == "last-known-good.json" {
			lkgWrites++
		}
		writeMu.Unlock()
		if isFirstLKG {
			if err := writeFileAtomic(path, data, perm); err != nil {
				return err
			}
			writeMu.Lock()
			firstPendingActive = true
			writeMu.Unlock()
			close(firstLKGWritten)
			<-secondStarted
			close(allowFirstActive)
			writeMu.Lock()
			firstPendingActive = false
			writeMu.Unlock()
			return nil
		}
		return writeFileAtomic(path, data, perm)
	}))

	firstDone := make(chan error, 1)
	go func() {
		_, err := store.ActivateProfile(context.Background(), policy.ProfileStrict)
		firstDone <- err
	}()
	<-firstLKGWritten

	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := store.ActivateProfile(context.Background(), policy.ProfileRelaxed)
		secondDone <- err
	}()

	<-allowFirstActive
	if err := <-firstDone; err != nil {
		t.Fatalf("first ActivateProfile() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second ActivateProfile() error = %v", err)
	}
	select {
	case got := <-interleaved:
		t.Fatalf("second activation wrote before first completed: %s", got)
	default:
	}
	if got := store.Current().Config.Profile; got != policy.ProfileRelaxed {
		t.Fatalf("Current() profile = %q, want relaxed", got)
	}
	if cfg := readConfigFile(t, store.activePath()); cfg.Profile != policy.ProfileRelaxed {
		t.Fatalf("active profile = %q, want relaxed", cfg.Profile)
	}
	if cfg := readConfigFile(t, store.lastKnownGoodPath()); cfg.Profile != policy.ProfileRelaxed {
		t.Fatalf("LKG profile = %q, want relaxed", cfg.Profile)
	}
}

func TestConcurrentStoreInstancesSerializeDiskWrites(t *testing.T) {
	root := t.TempDir()
	lockToken := make(chan struct{}, 1)
	lockToken <- struct{}{}
	lockAttempts := make(chan string, 10)
	firstLKGWritten := make(chan struct{})
	secondLockAttempted := make(chan struct{})
	allowFirstActive := make(chan struct{})
	interleaved := make(chan string, 1)

	locker := func(name string) func(context.Context) (func(), error) {
		return func(context.Context) (func(), error) {
			lockAttempts <- name
			<-lockToken
			return func() {
				lockToken <- struct{}{}
			}, nil
		}
	}

	var writeMu sync.Mutex
	firstPendingActive := false
	writer := func(path string, data []byte, perm os.FileMode) error {
		profile := "unknown"
		if strings.Contains(string(data), `"profile": "strict"`) {
			profile = "strict"
		} else if strings.Contains(string(data), `"profile": "relaxed"`) {
			profile = "relaxed"
		}

		writeMu.Lock()
		if firstPendingActive && profile == "relaxed" {
			select {
			case interleaved <- filepath.Base(path) + ":" + profile:
			default:
			}
		}
		writeMu.Unlock()

		isFirstLKG := filepath.Base(path) == "last-known-good.json" && profile == "strict"
		if isFirstLKG {
			if err := writeFileAtomic(path, data, perm); err != nil {
				return err
			}
			writeMu.Lock()
			firstPendingActive = true
			writeMu.Unlock()
			close(firstLKGWritten)
			<-secondLockAttempted
			close(allowFirstActive)
			writeMu.Lock()
			firstPendingActive = false
			writeMu.Unlock()
			return nil
		}
		return writeFileAtomic(path, data, perm)
	}

	firstStore := newStoreAt(t, root, withLocker(locker("first")), withWriter(writer))
	secondStore := newStoreAt(t, root, withLocker(locker("second")), withWriter(writer))

	firstDone := make(chan error, 1)
	go func() {
		_, err := firstStore.ActivateProfile(context.Background(), policy.ProfileStrict)
		firstDone <- err
	}()
	<-firstLKGWritten

	secondDone := make(chan error, 1)
	go func() {
		_, err := secondStore.ActivateProfile(context.Background(), policy.ProfileRelaxed)
		secondDone <- err
	}()

	for {
		if got := waitString(t, lockAttempts); got == "second" {
			close(secondLockAttempted)
			break
		}
	}
	<-allowFirstActive
	if err := <-firstDone; err != nil {
		t.Fatalf("first ActivateProfile() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second ActivateProfile() error = %v", err)
	}
	select {
	case got := <-interleaved:
		t.Fatalf("second store wrote before first completed: %s", got)
	default:
	}
	if got := secondStore.Current().Config.Profile; got != policy.ProfileRelaxed {
		t.Fatalf("Current() profile = %q, want relaxed", got)
	}
	if cfg := readConfigFile(t, secondStore.activePath()); cfg.Profile != policy.ProfileRelaxed {
		t.Fatalf("active profile = %q, want relaxed", cfg.Profile)
	}
	if cfg := readConfigFile(t, secondStore.lastKnownGoodPath()); cfg.Profile != policy.ProfileRelaxed {
		t.Fatalf("LKG profile = %q, want relaxed", cfg.Profile)
	}
}

func TestLoadRespectsCancellationWhileWaitingForPolicyLock(t *testing.T) {
	store := newStoreAt(t, t.TempDir(), withLocker(func(ctx context.Context) (func(), error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := store.Load(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Load() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestActivateRespectsCancellationWhileWaitingForPolicyLock(t *testing.T) {
	store := newStoreAt(t, t.TempDir(), withLocker(func(ctx context.Context) (func(), error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := store.ActivateProfile(ctx, policy.ProfileStrict)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ActivateProfile() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestActivateProfileUpdatesDiskAndMemory(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	snapshot, err := store.ActivateProfile(context.Background(), policy.ProfileStrict)
	if err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}
	if snapshot.Config.Profile != policy.ProfileStrict {
		t.Fatalf("profile = %q, want strict", snapshot.Config.Profile)
	}
	if store.Current().Config.Profile != policy.ProfileStrict {
		t.Fatalf("Current() profile = %q, want strict", store.Current().Config.Profile)
	}
	reopened := newStoreAt(t, store.root)
	loaded, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatalf("reopened Load() error = %v", err)
	}
	if loaded.Config.Profile != policy.ProfileStrict {
		t.Fatalf("reopened profile = %q, want strict", loaded.Config.Profile)
	}
	if loaded.ActivationID != snapshot.ActivationID {
		t.Fatalf("reopened activation ID = %q, want %q", loaded.ActivationID, snapshot.ActivationID)
	}
}

func TestActivateDoesNotKeepCallerConfigPointer(t *testing.T) {
	store := newTestStore(t)
	nonBypassableRules := true
	cfg := Config{
		Version:            policy.DefaultPolicyVersion,
		Profile:            policy.ProfileStrict,
		RulePack:           policy.DefaultRulePackID,
		NonBypassableRules: &nonBypassableRules,
	}

	snapshot, err := store.Activate(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	nonBypassableRules = false

	if !*snapshot.Config.NonBypassableRules {
		t.Fatalf("returned snapshot shares caller config pointer")
	}
	if !*store.Current().Config.NonBypassableRules {
		t.Fatalf("Current() shares caller config pointer")
	}
}

func TestCurrentDoesNotExposeStoredConfigPointer(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	snapshot := store.Current()
	*snapshot.Config.NonBypassableRules = false

	if !*store.Current().Config.NonBypassableRules {
		t.Fatalf("Current() exposed mutable stored config pointer")
	}
}

func TestLoadRecoversFromLastKnownGood(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.ActivateProfile(context.Background(), policy.ProfileStrict); err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}
	writeActive(t, store, `{"version":`)

	reopened := newStoreAt(t, store.root)
	snapshot, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Status != StatusRecoveredLKG || snapshot.Source != SourceLastKnownGood {
		t.Fatalf("source/status = %s/%s, want lkg/recovered", snapshot.Source, snapshot.Status)
	}
	if snapshot.Config.Profile != policy.ProfileStrict {
		t.Fatalf("profile = %q, want strict", snapshot.Config.Profile)
	}
}

func TestLoadFallsBackToDefaultWhenActiveAndLKGInvalid(t *testing.T) {
	store := newTestStore(t)
	writeActive(t, store, `{"version":`)
	writeLKG(t, store, `{
  "version": "guard-policy-v1",
  "profile": "balanced",
  "rulePack": "guard-default",
  "nonBypassableRules": false
}`)

	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Status != StatusDefaultedInvalid {
		t.Fatalf("status = %s, want %s", snapshot.Status, StatusDefaultedInvalid)
	}
	if snapshot.Config.Profile != policy.ProfileBalanced {
		t.Fatalf("profile = %q, want balanced", snapshot.Config.Profile)
	}
}

func TestValidationRejectsBadProfilesRulePacksAndBypassableRules(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "unknown profile",
			config: `{
  "version": "guard-policy-v1",
  "profile": "aggressive",
  "rulePack": "guard-default",
  "nonBypassableRules": true
}`,
		},
		{
			name: "unknown rule pack",
			config: `{
  "version": "guard-policy-v1",
  "profile": "balanced",
  "rulePack": "custom",
  "nonBypassableRules": true
}`,
		},
		{
			name: "missing nonBypassableRules",
			config: `{
  "version": "guard-policy-v1",
  "profile": "balanced",
  "rulePack": "guard-default"
}`,
		},
		{
			name: "false nonBypassableRules",
			config: `{
  "version": "guard-policy-v1",
  "profile": "balanced",
  "rulePack": "guard-default",
  "nonBypassableRules": false
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeConfig([]byte(tt.config)); !isValidationError(err) {
				t.Fatalf("decodeConfig() error = %T %v, want ValidationError", err, err)
			}
		})
	}
}

func TestDigestStableForSameConfig(t *testing.T) {
	cfg := DefaultConfig()
	got := mustConfigDigest(t, cfg)
	want := mustConfigDigest(t, cfg)
	if got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	cfg.Profile = policy.ProfileStrict
	got = mustConfigDigest(t, DefaultConfig())
	want = mustConfigDigest(t, cfg)
	if got == want {
		t.Fatalf("digest did not change after profile changed")
	}
}

func TestDigestReturnsValidationError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Profile = "invalid"
	if _, err := configDigest(cfg); !isValidationError(err) {
		t.Fatalf("configDigest() error = %T %v, want ValidationError", err, err)
	}
}

func TestWrittenFilesAreUserOnly(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertFileMode(t, store.activePath(), fileMode)
	assertFileMode(t, store.lastKnownGoodPath(), fileMode)

	if _, err := store.ActivateProfile(context.Background(), policy.ProfileStrict); err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}
	assertFileMode(t, store.activePath(), fileMode)
	assertFileMode(t, store.lastKnownGoodPath(), fileMode)
}

func TestCurrentSupportsConcurrentReads(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if got := store.Current(); got.ConfigDigest == "" {
					t.Errorf("Current() returned empty digest")
				}
			}
		}()
	}
	wg.Wait()
}

func TestSnapshotConvertsToPolicyConfigAndMetadata(t *testing.T) {
	store := newTestStore(t)
	snapshot, err := store.ActivateProfile(context.Background(), policy.ProfileRelaxed)
	if err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}

	engineConfig := snapshot.ToPolicyConfig()
	if engineConfig.Profile != policy.ProfileRelaxed || engineConfig.RulePack != policy.DefaultRulePackID {
		t.Fatalf("ToPolicyConfig() = %#v", engineConfig)
	}
	metadata := snapshot.DecisionMetadata()
	if metadata.PolicyVersion != policy.DefaultPolicyVersion || metadata.RulePackVersion != "v1" {
		t.Fatalf("DecisionMetadata() = %#v", metadata)
	}
	if metadata.ConfigSource != string(SourceActiveFile) || metadata.ConfigStatus != string(StatusOK) {
		t.Fatalf("DecisionMetadata() source/status = %s/%s", metadata.ConfigSource, metadata.ConfigStatus)
	}
	if !metadata.NonBypassableRules {
		t.Fatalf("DecisionMetadata() NonBypassableRules = false, want true")
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return newStoreAt(t, t.TempDir())
}

func newStoreAt(t *testing.T, root string, opts ...Option) *Store {
	t.Helper()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	opts = append([]Option{WithClock(func() time.Time { return now })}, opts...)
	store, err := Open(root, opts...)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", root, err)
	}
	return store
}

func writeActive(t *testing.T, store *Store, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(store.activePath()), dirMode); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(store.activePath(), []byte(data), fileMode); err != nil {
		t.Fatalf("WriteFile(active) error = %v", err)
	}
}

func writeLKG(t *testing.T, store *Store, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(store.lastKnownGoodPath()), dirMode); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(store.lastKnownGoodPath(), []byte(data), fileMode); err != nil {
		t.Fatalf("WriteFile(lkg) error = %v", err)
	}
}

func readActive(t *testing.T, store *Store) string {
	t.Helper()
	data, err := os.ReadFile(store.activePath())
	if err != nil {
		t.Fatalf("ReadFile(active) error = %v", err)
	}
	return string(data)
}

func readConfigFile(t *testing.T, path string) Config {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		t.Fatalf("decodeConfig(%s) error = %v", path, err)
	}
	return cfg
}

func mustConfigDigest(t *testing.T, cfg Config) string {
	t.Helper()
	digest, err := configDigest(cfg)
	if err != nil {
		t.Fatalf("configDigest() error = %v", err)
	}
	return digest
}

func waitString(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for channel value")
		return ""
	}
}

func seedCurrent(store *Store, snapshot Snapshot) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.current = cloneSnapshot(snapshot)
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}
