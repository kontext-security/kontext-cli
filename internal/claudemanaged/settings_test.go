package claudemanaged

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTemplateIncludesManagedKontextHooks(t *testing.T) {
	t.Parallel()

	settings := Template("/opt/kontext/bin/kontext")
	if len(settings.Hooks) != len(SupportedEvents) {
		t.Fatalf("hooks count = %d, want %d", len(settings.Hooks), len(SupportedEvents))
	}
	if settings.AllowManagedHooksOnly != nil {
		t.Fatal("AllowManagedHooksOnly set, want omitted")
	}
	if settings.DisableAllHooks != nil {
		t.Fatal("DisableAllHooks set, want omitted")
	}

	for _, event := range SupportedEvents {
		groups := settings.Hooks[event.Name.String()]
		if len(groups) != 1 {
			t.Fatalf("%s groups = %d, want 1", event.Name, len(groups))
		}
		if groups[0].Matcher != "" {
			t.Fatalf("%s matcher = %q, want empty", event.Name, groups[0].Matcher)
		}
		if len(groups[0].Hooks) != 1 {
			t.Fatalf("%s handlers = %d, want 1", event.Name, len(groups[0].Hooks))
		}
		handler := groups[0].Hooks[0]
		if handler.Type != "command" {
			t.Fatalf("%s handler type = %q, want command", event.Name, handler.Type)
		}
		if handler.Command != "/opt/kontext/bin/kontext" {
			t.Fatalf("%s command = %q, want binary path", event.Name, handler.Command)
		}
		wantArgs := []string{"hook", event.Alias}
		if !sameStrings(handler.Args, wantArgs) {
			t.Fatalf("%s args = %q, want %q", event.Name, handler.Args, wantArgs)
		}
		if handler.Timeout != DefaultHookTimeout {
			t.Fatalf("%s timeout = %d, want %d", event.Name, handler.Timeout, DefaultHookTimeout)
		}
	}
}

func TestTemplateJSONUsesExecForm(t *testing.T) {
	t.Parallel()

	data, err := TemplateJSON("/usr/local/bin/kontext")
	if err != nil {
		t.Fatalf("TemplateJSON() error = %v", err)
	}
	if strings.Contains(string(data), "/usr/local/bin/kontext hook") {
		t.Fatalf("template contains shell-form command: %s", data)
	}

	var decoded Settings
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if err := Validate(data, "/usr/local/bin/kontext"); err != nil {
		t.Fatalf("Validate(template) error = %v", err)
	}
}

func TestTemplateTrimsKontextBinary(t *testing.T) {
	t.Parallel()

	settings := Template(" /usr/local/bin/kontext ")
	handler := settings.Hooks["PreToolUse"][0].Hooks[0]
	if handler.Command != "/usr/local/bin/kontext" {
		t.Fatalf("command = %q, want trimmed binary path", handler.Command)
	}
}

func TestManagedSettingsPathForGOOS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		goos string
		want string
	}{
		{goos: "darwin", want: ManagedSettingsPath},
		{goos: "linux", want: LinuxManagedSettingsPath},
		{goos: "windows", want: WindowsManagedSettingsPath},
		{goos: "freebsd", want: ManagedSettingsPath},
	}

	for _, tt := range tests {
		if got := managedSettingsPathForGOOS(tt.goos); got != tt.want {
			t.Fatalf("managedSettingsPathForGOOS(%q) = %q, want %q", tt.goos, got, tt.want)
		}
	}
}

func TestValidateRejectsInvalidManagedSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(Settings) Settings
		wantErr string
	}{
		{
			name: "missing event",
			mutate: func(settings Settings) Settings {
				delete(settings.Hooks, "SessionEnd")
				return settings
			},
			wantErr: "SessionEnd hook missing",
		},
		{
			name: "shell form",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks[0].Command = "/usr/local/bin/kontext hook pre-tool-use"
				settings.Hooks["PreToolUse"][0].Hooks[0].Args = nil
				return settings
			},
			wantErr: "PreToolUse uses shell-form Kontext command",
		},
		{
			name: "shell form after valid handler",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks = append(settings.Hooks["PreToolUse"][0].Hooks, Handler{
					Type:    "command",
					Command: "/usr/local/bin/kontext hook pre-tool-use",
				})
				return settings
			},
			wantErr: "PreToolUse uses shell-form Kontext command",
		},
		{
			name: "quoted shell form after valid handler",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks = append(settings.Hooks["PreToolUse"][0].Hooks, Handler{
					Type:    "command",
					Command: "'/usr/local/bin/kontext' hook pre-tool-use",
				})
				return settings
			},
			wantErr: "PreToolUse uses shell-form Kontext command",
		},
		{
			name: "unrelated command mentions kontext hook",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks = append(settings.Hooks["PreToolUse"][0].Hooks, Handler{
					Type:    "command",
					Command: `/bin/echo "kontext hook pre-tool-use"`,
				})
				return settings
			},
		},
		{
			name: "missing args",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks[0].Args = nil
				return settings
			},
			wantErr: "PreToolUse Kontext handler args missing",
		},
		{
			name: "restrictive matcher",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Matcher = "Bash"
				return settings
			},
			wantErr: "PreToolUse Kontext command hook uses matcher \"Bash\"",
		},
		{
			name: "wrong handler type",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks[0].Type = "prompt"
				return settings
			},
			wantErr: "PreToolUse Kontext handler type = \"prompt\", want command",
		},
		{
			name: "disable all hooks",
			mutate: func(settings Settings) Settings {
				value := true
				settings.DisableAllHooks = &value
				return settings
			},
			wantErr: "disableAllHooks must not be true",
		},
		{
			name: "managed hooks only allowed",
			mutate: func(settings Settings) Settings {
				value := true
				settings.AllowManagedHooksOnly = &value
				return settings
			},
		},
		{
			name: "unrelated settings ignored",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreCompact"] = []MatcherGroup{{
					Matcher: "",
					Hooks: []Handler{{
						Type:    "command",
						Command: "/bin/echo",
						Args:    []string{"ok"},
					}},
				}}
				return settings
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			settings := tt.mutate(Template("/usr/local/bin/kontext"))
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			err = Validate(data, "/usr/local/bin/kontext")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseEventAlias(t *testing.T) {
	t.Parallel()

	got, ok := ParseEventAlias("pre-tool-use")
	if !ok {
		t.Fatal("ParseEventAlias() ok = false")
	}
	if got.String() != "PreToolUse" {
		t.Fatalf("ParseEventAlias() = %q, want PreToolUse", got)
	}
	if _, ok := ParseEventAlias("pretooluse"); ok {
		t.Fatal("ParseEventAlias(pretooluse) ok = true, want false")
	}
}
