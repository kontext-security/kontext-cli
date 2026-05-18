package hermes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"gopkg.in/yaml.v3"
)

func TestPrepareLocalLaunchUsesTemporaryProfileHome(t *testing.T) {
	home := t.TempDir()
	sourceHome := filepath.Join(home, ".hermes")
	if err := os.MkdirAll(sourceHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, "config.yaml"), []byte("model: test-model\nhooks:\n  pre_tool_call:\n    - command: existing-hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, ".env"), []byte("ANTHROPIC_API_KEY=test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("HERMES_HOME", sourceHome)

	launch, err := (&Hermes{}).PrepareLocalLaunch(agent.LocalLaunchOptions{
		SessionDir:    filepath.Join(home, "session"),
		KontextBinary: "/usr/local/bin/kontext",
		AgentName:     "hermes",
		SocketPath:    "/tmp/kontext.sock",
		Mode:          "observe",
		BaseEnv:       []string{"PATH=/usr/bin"},
		ExtraArgs:     []string{"--help"},
	})
	if err != nil {
		t.Fatalf("PrepareLocalLaunch() error = %v", err)
	}
	if !reflect.DeepEqual(launch.Args, []string{"--help"}) {
		t.Fatalf("launch args = %v, want [--help]", launch.Args)
	}
	hermesHome := envValue(launch.Env, "HERMES_HOME")
	if hermesHome == "" {
		t.Fatal("launch env missing HERMES_HOME")
	}
	if filepath.Base(filepath.Dir(hermesHome)) != "profiles" {
		t.Fatalf("HERMES_HOME = %q, parent must be named profiles", hermesHome)
	}
	if hermesHome == sourceHome {
		t.Fatal("PrepareLocalLaunch reused source HERMES_HOME, want temporary session home")
	}
	if _, err := os.Lstat(filepath.Join(hermesHome, ".env")); err != nil {
		t.Fatalf("snapshot .env missing: %v", err)
	}

	config := readHermesConfig(t, filepath.Join(hermesHome, "config.yaml"))
	if got := config["model"]; got != "test-model" {
		t.Fatalf("model = %v, want preserved test-model", got)
	}
	hooks := config["hooks"].(map[string]any)
	preHooks := hooks["pre_tool_call"].([]any)
	postHooks := hooks["post_tool_call"].([]any)
	if len(preHooks) != 1 {
		t.Fatalf("pre_tool_call hooks len = %d, want only Kontext hook", len(preHooks))
	}
	if len(postHooks) != 1 {
		t.Fatalf("post_tool_call hooks len = %d, want only Kontext hook", len(postHooks))
	}
	wantCommand := `'/usr/local/bin/kontext' hook --agent 'hermes' --mode 'observe' --socket '/tmp/kontext.sock'`
	if got := preHooks[0].(map[string]any)["command"]; got != wantCommand {
		t.Fatalf("pre hook command = %q, want %q", got, wantCommand)
	}
	if got := postHooks[0].(map[string]any)["command"]; got != wantCommand {
		t.Fatalf("post hook command = %q, want %q", got, wantCommand)
	}

	allowlist := readAllowlist(t, filepath.Join(hermesHome, "shell-hooks-allowlist.json"))
	if len(allowlist.Approvals) != 2 {
		t.Fatalf("allowlist approvals len = %d, want 2", len(allowlist.Approvals))
	}
	for _, approval := range allowlist.Approvals {
		if approval.Command != wantCommand {
			t.Fatalf("allowlist command = %q, want %q", approval.Command, wantCommand)
		}
		if approval.Event != "pre_tool_call" && approval.Event != "post_tool_call" {
			t.Fatalf("allowlist event = %q, want Kontext hook event", approval.Event)
		}
	}
}

func TestResolveHermesSourceHonorsExplicitHomeBeforeActiveProfile(t *testing.T) {
	home := t.TempDir()
	explicitHome := filepath.Join(home, "custom-hermes")
	defaultProfile := filepath.Join(home, ".hermes", "profiles", "work")
	if err := os.MkdirAll(explicitHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(defaultProfile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".hermes", "active_profile"), []byte("work\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("HERMES_HOME", explicitHome)

	source := resolveHermesSource()
	if source.Home != explicitHome {
		t.Fatalf("source home = %q, want explicit HERMES_HOME %q", source.Home, explicitHome)
	}
	if source.Root != explicitHome {
		t.Fatalf("source root = %q, want explicit root %q", source.Root, explicitHome)
	}
}

func TestGenerateLocalHermesHomeCopiesAuthSnapshotWithoutSymlinks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	sourceRoot := filepath.Join(root, "source")
	sourceHome := filepath.Join(sourceRoot, "profiles", "work")
	if err := os.MkdirAll(filepath.Join(sourceHome, "auth"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, "config.yaml"), []byte("model: test-model\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "auth.json"), []byte(`{"root":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, "auth.json"), []byte(`{"profile":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, "auth", "google_oauth.json"), []byte(`{"token":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, "SOUL.md"), []byte("persona"), 0o600); err != nil {
		t.Fatal(err)
	}

	hermesHome, err := generateLocalHermesHome(filepath.Join(root, "session"), hermesSource{Home: sourceHome, Root: sourceRoot}, "/usr/local/bin/kontext", "hermes", "/tmp/kontext.sock", "observe")
	if err != nil {
		t.Fatalf("generateLocalHermesHome() error = %v", err)
	}
	hermesRoot := filepath.Dir(filepath.Dir(hermesHome))
	for _, path := range []string{
		filepath.Join(hermesRoot, "auth.json"),
		filepath.Join(hermesHome, "auth.json"),
		filepath.Join(hermesHome, "auth", "google_oauth.json"),
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("snapshot path %s missing: %v", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("snapshot path %s is symlink, want copied file", path)
		}
	}
	if _, err := os.Lstat(filepath.Join(hermesHome, "SOUL.md")); !os.IsNotExist(err) {
		t.Fatalf("SOUL.md snapshot err = %v, want not copied", err)
	}
}

func readHermesConfig(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	var config map[string]any
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", path, err)
	}
	return config
}

func readAllowlist(t *testing.T, path string) shellHookAllowlist {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	var allowlist shellHookAllowlist
	if err := json.Unmarshal(data, &allowlist); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", path, err)
	}
	return allowlist
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix)
		}
	}
	return ""
}
