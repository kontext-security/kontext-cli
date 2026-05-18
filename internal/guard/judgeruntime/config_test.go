package judgeruntime

import (
	"path/filepath"
	"testing"
)

func TestConfigFromEnvDefaultsManagedJudgeOn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	cfg, err := ConfigFromEnv(dbPath, true)
	if err != nil {
		t.Fatalf("ConfigFromEnv() error = %v", err)
	}
	if !cfg.Managed {
		t.Fatal("Managed = false, want true")
	}
	if cfg.CacheDir != filepath.Join(filepath.Dir(dbPath), "judge-models") {
		t.Fatalf("CacheDir = %q, want db-adjacent judge-models", cfg.CacheDir)
	}
}

func TestConfigFromEnvTreatsJudgeURLAsExternalByDefault(t *testing.T) {
	t.Setenv("KONTEXT_JUDGE_URL", "http://127.0.0.1:18080")
	t.Setenv("KONTEXT_JUDGE_MODEL", "qwen3")

	cfg, err := ConfigFromEnv(filepath.Join(t.TempDir(), "guard.db"), true)
	if err != nil {
		t.Fatalf("ConfigFromEnv() error = %v", err)
	}
	if cfg.Managed {
		t.Fatal("Managed = true, want false for explicit judge URL")
	}
}
