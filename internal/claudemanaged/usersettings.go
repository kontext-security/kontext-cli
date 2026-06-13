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
)

// User-level Claude Code settings (~/.claude/settings.json) integration for
// self-serve installs. Unlike the MDM managed-settings drop-in (root-owned,
// tamper-resistant), this file belongs to the user: the merge must preserve
// every byte of foreign content (their hooks, permissions, env, unknown
// keys), be idempotent, and be cleanly reversible.

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
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
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
	fields, ok := splitHookCommand(command)
	if !ok || len(fields) != 3 || strings.Contains(command, "--") {
		return false
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

func splitHookCommand(command string) ([]string, bool) {
	var fields []string
	var builder strings.Builder
	var quote rune
	inField := false

	for _, char := range command {
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
				continue
			}
			builder.WriteRune(char)
			inField = true
		case char == '\'' || char == '"':
			quote = char
			inField = true
		case char == ' ' || char == '\t' || char == '\n' || char == '\r':
			if inField {
				fields = append(fields, builder.String())
				builder.Reset()
				inField = false
			}
		default:
			builder.WriteRune(char)
			inField = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	if inField {
		fields = append(fields, builder.String())
	}
	return fields, true
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

	hooks, err := hooksMap(settings)
	if err != nil {
		return nil, err
	}

	if hasGuardHooks(hooks) {
		warnings = append(warnings, "Kontext Guard hooks are also installed; consider `kontext guard hooks uninstall claude-code` to avoid duplicate processing")
	}

	// Build every canonical group before touching the map, so an error can
	// never leave the caller's settings half-merged.
	template := Template(kontextBinary)
	canonical := make(map[string]any, len(SupportedEvents))
	for _, event := range SupportedEvents {
		name := event.Name.String()
		group, err := toAny(template.Hooks[name][0])
		if err != nil {
			return nil, err
		}
		canonical[name] = group
	}

	settings["hooks"] = hooks
	for _, event := range SupportedEvents {
		name := event.Name.String()
		hooks[name] = append(withoutManagedHandlers(hooks[name]), canonical[name])
	}
	return warnings, nil
}

// RemoveManagedHooks strips OUR handlers (and only ours) from the settings
// map, pruning groups and event keys that end up empty. Foreign hooks,
// including Guard's, survive untouched. Idempotent.
func RemoveManagedHooks(settings map[string]any) error {
	hooks, err := hooksMap(settings)
	if err != nil {
		return err
	}
	for _, event := range SupportedEvents {
		name := event.Name.String()
		if _, present := hooks[name]; !present {
			continue
		}
		groups := withoutManagedHandlers(hooks[name])
		if len(groups) == 0 {
			delete(hooks, name)
			continue
		}
		hooks[name] = groups
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	}
	return nil
}

func hooksMap(settings map[string]any) (map[string]any, error) {
	switch value := settings["hooks"].(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return value, nil
	default:
		// Never clobber a shape we don't understand — the file is the user's.
		return nil, errors.New("settings.json hooks must be a JSON object")
	}
}

// withoutManagedHandlers filters our handlers out of every matcher group of
// an event's group list, dropping groups left without handlers. Unparseable
// entries are kept verbatim (they are the user's data, not ours to judge).
func withoutManagedHandlers(raw any) []any {
	list, ok := raw.([]any)
	if !ok {
		if raw == nil {
			return nil
		}
		return []any{raw}
	}
	filtered := make([]any, 0, len(list))
	for _, entry := range list {
		group, ok := entry.(map[string]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		handlers, ok := group["hooks"].([]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		kept := make([]any, 0, len(handlers))
		for _, handler := range handlers {
			if handlerMap, ok := handler.(map[string]any); ok {
				if command, ok := handlerMap["command"].(string); ok && IsManagedHookCommand(command) {
					continue
				}
			}
			kept = append(kept, handler)
		}
		if len(kept) == 0 {
			continue
		}
		group["hooks"] = kept
		filtered = append(filtered, group)
	}
	return filtered
}

func hasGuardHooks(hooks map[string]any) bool {
	for _, raw := range hooks {
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, entry := range list {
			group, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			handlers, _ := group["hooks"].([]any)
			for _, handler := range handlers {
				handlerMap, ok := handler.(map[string]any)
				if !ok {
					continue
				}
				if command, ok := handlerMap["command"].(string); ok && IsGuardHookCommand(command) {
					return true
				}
			}
		}
	}
	return false
}

// toAny round-trips a typed value through JSON so it lands in the generic
// settings map with exactly the shape WriteUserSettings will serialize.
func toAny(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
