package claudemanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

const (
	ManagedSettingsPath        = "/Library/Application Support/ClaudeCode/managed-settings.json"
	LinuxManagedSettingsPath   = "/etc/claude-code/managed-settings.json"
	WindowsManagedSettingsPath = `C:\Program Files\ClaudeCode\managed-settings.json`
	DefaultKontextBinary       = "/usr/local/bin/kontext"
	DefaultHookTimeout         = 20
)

type Event struct {
	Name  hook.HookName
	Alias string
}

var SupportedEvents = []Event{
	{Name: hook.HookSessionStart, Alias: "session-start"},
	{Name: hook.HookPreToolUse, Alias: "pre-tool-use"},
	{Name: hook.HookPostToolUse, Alias: "post-tool-use"},
	{Name: hook.HookPostToolUseFailed, Alias: "post-tool-use-failure"},
	{Name: hook.HookSessionEnd, Alias: "session-end"},
}

func DefaultManagedSettingsPath() string {
	return managedSettingsPathForGOOS(runtime.GOOS)
}

func managedSettingsPathForGOOS(goos string) string {
	switch goos {
	case "windows":
		return WindowsManagedSettingsPath
	case "linux":
		return LinuxManagedSettingsPath
	default:
		return ManagedSettingsPath
	}
}

type Settings struct {
	Hooks                 map[string][]MatcherGroup `json:"hooks"`
	DisableAllHooks       *bool                     `json:"disableAllHooks,omitempty"`
	AllowManagedHooksOnly *bool                     `json:"allowManagedHooksOnly,omitempty"`
}

type MatcherGroup struct {
	Matcher string    `json:"matcher"`
	Hooks   []Handler `json:"hooks"`
}

type Handler struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}

func Template(kontextBinary string) Settings {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}
	settings := Settings{Hooks: make(map[string][]MatcherGroup, len(SupportedEvents))}
	for _, event := range SupportedEvents {
		settings.Hooks[event.Name.String()] = []MatcherGroup{{
			Matcher: "",
			Hooks: []Handler{{
				Type:    "command",
				Command: kontextBinary,
				Args:    []string{"hook", event.Alias},
				Timeout: DefaultHookTimeout,
			}},
		}}
	}
	return settings
}

func TemplateJSON(kontextBinary string) ([]byte, error) {
	data, err := json.MarshalIndent(Template(kontextBinary), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal managed settings template: %w", err)
	}
	return append(data, '\n'), nil
}

func Validate(data []byte, kontextBinary string) error {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse managed settings: %w", err)
	}

	var problems []string
	if settings.Hooks == nil {
		problems = append(problems, "hooks missing")
	}
	if settings.DisableAllHooks != nil && *settings.DisableAllHooks {
		problems = append(problems, "disableAllHooks must not be true")
	}

	for _, event := range SupportedEvents {
		if err := validateEvent(settings.Hooks[event.Name.String()], event, kontextBinary); err != nil {
			problems = append(problems, err.Error())
		}
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func ParseEventAlias(value string) (hook.HookName, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, event := range SupportedEvents {
		if normalized == event.Alias {
			return event.Name, true
		}
	}
	return "", false
}

func AliasForEvent(name hook.HookName) (string, bool) {
	for _, event := range SupportedEvents {
		if event.Name == name {
			return event.Alias, true
		}
	}
	return "", false
}

func validateEvent(groups []MatcherGroup, event Event, kontextBinary string) error {
	if len(groups) == 0 {
		return fmt.Errorf("%s hook missing", event.Name)
	}

	wantArgs := []string{"hook", event.Alias}
	foundValid := false
	foundRestrictiveMatcher := false
	for _, group := range groups {
		for _, handler := range group.Hooks {
			if isShellFormKontextHandler(handler, kontextBinary) {
				return fmt.Errorf("%s uses shell-form Kontext command; use command plus args", event.Name)
			}
			if handler.Command != kontextBinary {
				continue
			}
			if handler.Type != "command" {
				return fmt.Errorf("%s Kontext handler type = %q, want command", event.Name, handler.Type)
			}
			if len(handler.Args) == 0 {
				return fmt.Errorf("%s Kontext handler args missing", event.Name)
			}
			if !sameStrings(handler.Args, wantArgs) {
				return fmt.Errorf("%s Kontext handler args = %q, want %q", event.Name, handler.Args, wantArgs)
			}
			if !isAllMatcher(group.Matcher) {
				foundRestrictiveMatcher = true
				continue
			}
			foundValid = true
		}
	}

	if foundValid {
		return nil
	}
	if foundRestrictiveMatcher {
		return fmt.Errorf("%s Kontext command hook uses matcher %q; use an empty matcher for full event coverage", event.Name, firstRestrictiveMatcher(groups, kontextBinary, wantArgs))
	}
	return fmt.Errorf("%s Kontext command hook missing for %s", event.Name, kontextBinary)
}

func isShellFormKontextHandler(handler Handler, kontextBinary string) bool {
	if len(handler.Args) > 0 {
		return false
	}
	command := strings.TrimSpace(handler.Command)
	if command == "" {
		return false
	}
	command = strings.NewReplacer("'", "", `"`, "").Replace(command)
	fields := strings.Fields(command)
	if len(fields) < 2 || fields[1] != "hook" {
		return false
	}
	if fields[0] == kontextBinary {
		return true
	}
	base := filepath.Base(kontextBinary)
	return base == "kontext" && fields[0] == "kontext"
}

func isAllMatcher(value string) bool {
	matcher := strings.TrimSpace(value)
	return matcher == "" || matcher == "*"
}

func firstRestrictiveMatcher(groups []MatcherGroup, kontextBinary string, wantArgs []string) string {
	for _, group := range groups {
		for _, handler := range group.Hooks {
			if handler.Command == kontextBinary && handler.Type == "command" && sameStrings(handler.Args, wantArgs) && !isAllMatcher(group.Matcher) {
				return group.Matcher
			}
		}
	}
	return ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
