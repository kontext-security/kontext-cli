package claudemanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/agenthooks"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

// User-level Claude Code settings (~/.claude/settings.json) integration for
// self-serve installs. Unlike the MDM managed-settings drop-in (root-owned,
// tamper-resistant), this file belongs to the user: the merge must preserve
// foreign JSON content (their hooks, permissions, env, unknown keys), be
// idempotent, and be cleanly reversible.

// UserSettingsPath returns ~/.claude/settings.json, creating ~/.claude.
func UserSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(claudeDir, "settings.json"), nil
}

// ReadUserSettings parses the settings file into a generic map so unknown
// keys survive a read-merge-write round trip. A missing file is an empty map.
func ReadUserSettings(path string) (map[string]any, error) {
	settings := map[string]any{}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("parse Claude settings: %w", err)
	}
	return settings, nil
}

// WriteUserSettings writes the settings back atomically (temp file + rename,
// so a crash mid-write can never leave a truncated settings.json behind),
// preserving the existing file's permission bits (a user may keep their
// settings private); new files are created 0600.
func WriteUserSettings(path string, settings map[string]any) error {
	writePath := path
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		writePath = target
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	mode := fs.FileMode(0o600)
	if info, err := os.Stat(writePath); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(writePath), ".settings-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, writePath)
}

// BackupUserSettings copies the file aside (timestamped, same permissions)
// before a mutation. Missing file is a no-op.
func BackupUserSettings(path, label string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	backupPathPrefix := fmt.Sprintf("%s.%s-backup-%s", path, label, time.Now().UTC().Format("20060102T150405.000000000Z"))
	var file *os.File
	for attempt := 0; attempt < 100; attempt++ {
		backupPath := backupPathPrefix
		if attempt > 0 {
			backupPath = fmt.Sprintf("%s-%d", backupPathPrefix, attempt)
		}
		file, err = os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if file == nil {
		return fmt.Errorf("create backup for %s: too many timestamp collisions", path)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// IsGuardHookCommand reports whether a hook command belongs to Kontext Guard
// (the local-only enforcement product). Shared with guard/cli so the two
// installers agree on whose entries are whose.
func IsGuardHookCommand(command string) bool {
	normalized := strings.ReplaceAll(command, "'", "")
	return strings.Contains(normalized, "kontext guard hook claude-code") ||
		(strings.Contains(normalized, "kontext hook --agent claude") && strings.Contains(normalized, "--mode"))
}

// IsManagedHookCommand reports whether a hook command is one of OURS: the
// flagless managed-observe form `'<binary>' hook '<alias>'`. Guard hooks
// (`kontext guard hook claude-code`, `kontext hook --agent claude … --mode …`)
// are deliberately excluded so the two installers never touch each other's
// entries. Matching on the alias rather than the exact binary path means a
// re-run after the binary moved (brew prefix change) replaces stale entries.
func IsManagedHookCommand(command string) bool {
	fields, ok := agenthooks.SplitCommand(command)
	if !ok {
		return false
	}
	return isManagedHookFields(fields)
}

func isGuardHookHandler(handler agenthooks.CommandHandler) bool {
	if len(handler.Args) == 0 {
		return IsGuardHookCommand(handler.Command)
	}
	fields, ok := commandHandlerFields(handler)
	if !ok {
		return false
	}
	return isGuardHookFields(fields)
}

func isManagedHookHandler(handler agenthooks.CommandHandler) bool {
	if len(handler.Args) == 0 {
		return IsManagedHookCommand(handler.Command)
	}
	fields, ok := commandHandlerFields(handler)
	if !ok {
		return false
	}
	return isManagedHookFields(fields)
}

func commandHandlerFields(handler agenthooks.CommandHandler) ([]string, bool) {
	command := strings.TrimSpace(handler.Command)
	if command == "" {
		return nil, false
	}
	if fields, ok := agenthooks.SplitCommand(command); ok && len(fields) == 1 {
		command = fields[0]
	}
	fields := make([]string, 0, 1+len(handler.Args))
	fields = append(fields, command)
	fields = append(fields, handler.Args...)
	return fields, true
}

func isGuardHookFields(fields []string) bool {
	if len(fields) < 4 || filepath.Base(fields[0]) != "kontext" {
		return false
	}
	if fields[1] == "guard" && fields[2] == "hook" && fields[3] == "claude-code" {
		return true
	}
	if fields[1] != "hook" || fields[2] != "--agent" || fields[3] != "claude" {
		return false
	}
	for _, field := range fields[4:] {
		if field == "--mode" {
			return true
		}
	}
	return false
}

func isManagedHookFields(fields []string) bool {
	if len(fields) != 3 {
		return false
	}
	for _, field := range fields {
		if strings.HasPrefix(field, "--") {
			return false
		}
	}
	if filepath.Base(fields[0]) != "kontext" || fields[1] != "hook" {
		return false
	}
	for _, event := range SupportedEvents {
		if fields[2] == event.Alias {
			return true
		}
	}
	return false
}

// MergeManagedHooks installs/refreshes the five managed-observe hooks in the
// settings map: for each supported event it removes any existing Kontext
// managed handlers (stale binary paths included) and appends the canonical
// group from Template. Everything else in the map is untouched. Idempotent:
// merging twice is a fixpoint. Returns non-fatal warnings for conditions the
// user should know about.
func MergeManagedHooks(settings map[string]any, kontextBinary string) ([]string, error) {
	var warnings []string

	if disabled, ok := settings["disableAllHooks"].(bool); ok && disabled {
		warnings = append(warnings, "Claude Code hooks are globally disabled (disableAllHooks) in settings.json; Kontext hooks will not fire until you remove that setting")
	}

	config := agenthooks.Config{
		Settings:         settings,
		HooksDescription: "settings.json hooks",
	}
	hooks, err := config.HooksMap()
	if err != nil {
		return nil, err
	}

	if agenthooks.HasCommand(hooks, isGuardHookHandler) {
		warnings = append(warnings, "Kontext Guard hooks are also installed; consider `kontext guard hooks uninstall claude-code` to avoid duplicate processing")
	}

	// Build the typed plan before touching the map, so an error can
	// never leave the caller's settings half-merged.
	plan := managedHookPlan(kontextBinary)
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	if err := config.Merge(plan, isManagedHookHandler); err != nil {
		return nil, err
	}
	return warnings, nil
}

func managedHookPlan(kontextBinary string) agenthooks.Plan {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}

	events := make(map[hook.HookName]agenthooks.EventPlan, len(SupportedEvents))
	for _, event := range SupportedEvents {
		handler := agenthooks.CommandHook{
			Command: hookCommand(kontextBinary, event.Alias),
			Timeout: DefaultHookTimeout,
		}
		if event.Async {
			value := true
			handler.Async = &value
		}
		events[event.Name] = agenthooks.EventPlan{
			Match: agenthooks.MatchSpec{
				Pattern: "",
			},
			Command:   handler,
			Placement: agenthooks.PlacementAppend,
		}
	}

	return agenthooks.Plan{
		Version:  agenthooks.SchemaVersionV1,
		Provider: agenthooks.ProviderClaudeCode,
		Owner:    agenthooks.OwnerKontextManagedObserve,
		Events:   events,
	}
}

// RemoveManagedHooks strips OUR handlers (and only ours) from the settings
// map, pruning groups and event keys that end up empty. Foreign hooks,
// including Guard's, survive untouched. Idempotent.
func RemoveManagedHooks(settings map[string]any) error {
	config := agenthooks.Config{
		Settings:         settings,
		HooksDescription: "settings.json hooks",
	}
	return config.Remove(managedHookPlan(DefaultKontextBinary), isManagedHookHandler)
}
