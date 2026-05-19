package installation

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadMissingStateReturnsNotFound(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "installation.json"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadFile() error = %v, want ErrNotFound", err)
	}
}

func TestLoadExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	writeState(t, path, "ins_existing")

	state, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if state.InstallationID != "ins_existing" {
		t.Fatalf("InstallationID = %q, want ins_existing", state.InstallationID)
	}
}

func TestEnsureCreatesStateWith0600Permissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")

	state, err := EnsureFile(path)
	if err != nil {
		t.Fatalf("EnsureFile() error = %v", err)
	}
	if !validInstallationID(state.InstallationID) {
		t.Fatalf("InstallationID = %q, want ins_ format", state.InstallationID)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %v, want 0600", got)
	}
}

func TestEnsureConcurrentFirstCreateReturnsPersistedID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")

	const callers = 32
	var wg sync.WaitGroup
	results := make(chan State, callers)
	errs := make(chan error, callers)

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := EnsureFile(path)
			if err != nil {
				errs <- err
				return
			}
			results <- state
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("EnsureFile() error = %v", err)
	}
	persisted, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	for state := range results {
		if state.InstallationID != persisted.InstallationID {
			t.Fatalf("InstallationID = %q, want persisted %q", state.InstallationID, persisted.InstallationID)
		}
	}
}

func TestEnsureDoesNotResetExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	writeState(t, path, "ins_existing")

	state, err := EnsureFile(path)
	if err != nil {
		t.Fatalf("EnsureFile() error = %v", err)
	}
	if state.InstallationID != "ins_existing" {
		t.Fatalf("InstallationID = %q, want ins_existing", state.InstallationID)
	}
}

func TestLoadUsesEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	writeState(t, path, "ins_env")
	t.Setenv(EnvPath, path)

	state, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if state.InstallationID != "ins_env" {
		t.Fatalf("InstallationID = %q, want ins_env", state.InstallationID)
	}
}

func writeState(t *testing.T, path string, id string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"installation_id":"`+id+`"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
