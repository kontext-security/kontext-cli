package claudemanaged

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func eventGroups(t *testing.T, settings map[string]any, event string) []any {
	t.Helper()
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks missing or not an object: %T", settings["hooks"])
	}
	groups, ok := hooks[event].([]any)
	if !ok {
		t.Fatalf("event %s missing or not a list: %T", event, hooks[event])
	}
	return groups
}

func TestRemoveManagedHooksLeavesForeignContent(t *testing.T) {
	settings := decode(t, `{
		"permissions": {"allow": ["Bash(ls:*)"]},
		"hooks": {
			"SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "'/usr/local/bin/kontext' hook 'session-start'"}]}],
			"PreToolUse": [
				{"matcher": "", "hooks": [{"type": "command", "command": "'/usr/local/bin/kontext' hook 'pre-tool-use'"}]},
				{"matcher": "Edit", "hooks": [{"type": "command", "command": "lint-check"}]}
			],
			"PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "'/usr/local/bin/kontext' hook 'post-tool-use'"}]}],
			"SessionEnd": [{"matcher": "", "hooks": [{"type": "command", "command": "'/usr/local/bin/kontext' hook 'session-end'"}]}]
		}
	}`)

	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}

	hooks := settings["hooks"].(map[string]any)
	// Events that only held our hooks are pruned entirely.
	for _, event := range []string{"SessionStart", "PostToolUse", "SessionEnd"} {
		if _, present := hooks[event]; present {
			t.Fatalf("%s not pruned after removal", event)
		}
	}
	// The foreign PreToolUse hook survives alone.
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Edit" {
		t.Fatalf("foreign PreToolUse hook lost: %v", pre)
	}
	if _, ok := settings["permissions"]; !ok {
		t.Fatal("permissions clobbered by removal")
	}
}

func TestRemoveManagedHooksDropsEmptyHooksKey(t *testing.T) {
	settings := decode(t, `{"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "'/usr/local/bin/kontext' hook 'pre-tool-use'"}]}]}}`)
	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}
	if _, present := settings["hooks"]; present {
		t.Fatalf("empty hooks key left behind: %v", settings["hooks"])
	}
}

func TestIsGuardHookCommand(t *testing.T) {
	cases := []struct {
		command string
		want    bool
	}{
		{"kontext guard hook claude-code", true},
		{"'/usr/local/bin/kontext' guard hook claude-code", true},
		{"'/usr/local/bin/kontext' hook --agent claude --event pre-tool-use --mode observe", true},
		// Managed-observe hooks must never match.
		{"'/usr/local/bin/kontext' hook 'pre-tool-use'", false},
		// --agent without --mode is not a guard hook.
		{"kontext hook --agent claude", false},
		{"say done", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsGuardHookCommand(tc.command); got != tc.want {
			t.Errorf("IsGuardHookCommand(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestIsManagedHookCommand(t *testing.T) {
	cases := []struct {
		command string
		want    bool
	}{
		{"'/usr/local/bin/kontext' hook 'pre-tool-use'", true},
		{"'/Users/o'\\''brien/bin/kontext' hook 'pre-tool-use'", true},
		{"'/Applications/Kontext CLI/kontext' hook 'pre-tool-use'", true},
		{"'/Users/dev/--tools/kontext' hook 'pre-tool-use'", true},
		{"'/opt/homebrew/bin/kontext' hook 'session-start'", true},
		{"/usr/local/bin/kontext hook session-end", true},
		{"'/usr/local/bin/kontext' hook 'unterminated", false},
		// Guard hooks must never match.
		{"'/usr/local/bin/kontext' hook --agent claude --event pre-tool-use --mode observe", false},
		{"kontext guard hook claude-code", false},
		// Foreign tools must never match.
		{"/usr/local/bin/other-tool hook pre-tool-use", false},
		{"/usr/local/bin/not-kontext hook pre-tool-use", false},
		{"my-kontext-helper hook session-end", false},
		{"say done", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsManagedHookCommand(tc.command); got != tc.want {
			t.Errorf("IsManagedHookCommand(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestReadWriteUserSettingsPreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	// New files are created private.
	if err := WriteUserSettings(path, map[string]any{"a": float64(1)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %v, want 0600", info.Mode().Perm())
	}

	// An existing file's (looser) mode is preserved, not tightened or loosened.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteUserSettings(path, map[string]any{"a": float64(2)}); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("rewritten file mode = %v, want 0644 preserved", info.Mode().Perm())
	}

	got, err := ReadUserSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"a": float64(2)}) {
		t.Fatalf("round trip = %v", got)
	}
}

func TestWriteUserSettingsPreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target-settings.json")
	firstLink := filepath.Join(dir, "first-settings.json")
	link := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(target, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, firstLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(firstLink, link); err != nil {
		t.Fatal(err)
	}

	if err := WriteUserSettings(link, map[string]any{"a": float64(2)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings path is no longer a symlink: mode=%v", info.Mode())
	}
	firstInfo, err := os.Lstat(firstLink)
	if err != nil {
		t.Fatal(err)
	}
	if firstInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("intermediate settings path is no longer a symlink: mode=%v", firstInfo.Mode())
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"a": 2`) {
		t.Fatalf("target content = %s, want rewritten target", data)
	}
}

func TestReadUserSettingsMissingFileIsEmpty(t *testing.T) {
	got, err := ReadUserSettings(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("missing file settings = %v, want empty", got)
	}
}

func TestReadUserSettingsMalformedJSONFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUserSettings(path); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestBackupUserSettingsPreservesModeAndContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := BackupUserSettings(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backup string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "kontext-setup-backup-") {
			backup = filepath.Join(dir, entry.Name())
		}
	}
	if backup == "" {
		t.Fatal("no backup file written")
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("backup mode = %v, want original 0640", info.Mode().Perm())
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"a":1}` {
		t.Fatalf("backup content = %s", data)
	}

	// Missing file is a no-op.
	if err := BackupUserSettings(filepath.Join(dir, "absent.json"), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestBackupUserSettingsDoesNotOverwriteExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BackupUserSettings(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	if err := BackupUserSettings(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "kontext-setup-backup-") {
			backups++
		}
	}
	if backups != 2 {
		t.Fatalf("backup count = %d, want 2", backups)
	}
}
