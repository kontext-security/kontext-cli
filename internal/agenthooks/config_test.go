package agenthooks

import "testing"

func TestConfigMergePreservesForeignHandlers(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "",
					"hooks": []any{
						map[string]any{"type": "command", "command": "owned old"},
						map[string]any{"type": "command", "command": "foreign"},
					},
				},
			},
			"PostToolUse": []any{
				map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": "foreign post"}}},
			},
		},
		"other": "value",
	}

	config := Config{Settings: settings}
	err := config.Merge(testPlan(map[string]string{"PreToolUse": "owned new"}), func(handler CommandHandler) bool {
		return handler.Command == "owned old" || handler.Command == "owned new"
	})
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}

	if settings["other"] != "value" {
		t.Fatalf("foreign top-level key changed: %v", settings["other"])
	}
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse groups = %d, want foreign group plus canonical group", len(pre))
	}
	firstHandlers := pre[0].(map[string]any)["hooks"].([]any)
	if len(firstHandlers) != 1 || firstHandlers[0].(map[string]any)["command"] != "foreign" {
		t.Fatalf("foreign handler not preserved: %v", firstHandlers)
	}
	secondHandlers := pre[1].(map[string]any)["hooks"].([]any)
	if len(secondHandlers) != 1 || secondHandlers[0].(map[string]any)["command"] != "owned new" {
		t.Fatalf("canonical handler not appended: %v", secondHandlers)
	}
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Fatal("unrelated event was removed")
	}
}

func TestConfigMergeUsesCustomHooksKey(t *testing.T) {
	settings := map[string]any{}
	config := Config{Settings: settings, HooksKey: "customHooks"}

	if err := config.Merge(testPlan(map[string]string{"PreToolUse": "owned"}), func(handler CommandHandler) bool {
		return handler.Command == "owned"
	}); err != nil {
		t.Fatalf("Merge() error = %v", err)
	}

	if _, ok := settings["hooks"]; ok {
		t.Fatalf("default hooks key was written: %v", settings)
	}
	if _, ok := settings["customHooks"].(map[string]any)["PreToolUse"]; !ok {
		t.Fatalf("custom hooks key missing PreToolUse: %v", settings)
	}
}

func TestConfigRemovePrunesOwnedHandlersOnly(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "",
					"hooks": []any{
						map[string]any{"type": "command", "command": "owned"},
						map[string]any{"type": "command", "command": "foreign"},
					},
				},
			},
			"PostToolUse": []any{
				map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": "owned"}}},
			},
		},
	}

	config := Config{Settings: settings}
	if err := config.Remove(testPlan(map[string]string{
		"PreToolUse":  "owned",
		"PostToolUse": "owned",
	}), func(handler CommandHandler) bool {
		return handler.Command == "owned"
	}); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	handlers := pre[0].(map[string]any)["hooks"].([]any)
	if len(handlers) != 1 || handlers[0].(map[string]any)["command"] != "foreign" {
		t.Fatalf("foreign handler not preserved: %v", handlers)
	}
	if _, present := hooks["PostToolUse"]; present {
		t.Fatalf("empty event was not pruned: %v", hooks["PostToolUse"])
	}
}

func TestConfigRemoveDropsEmptyHooksKey(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": "owned"}}},
			},
		},
	}

	config := Config{Settings: settings}
	if err := config.Remove(testPlan(map[string]string{"PreToolUse": "owned"}), func(handler CommandHandler) bool {
		return handler.Command == "owned"
	}); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, present := settings["hooks"]; present {
		t.Fatalf("hooks key remains after removing the last handler: %v", settings["hooks"])
	}
}

func TestConfigPreservesMalformedEventValues(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": "invalid",
		},
	}
	config := Config{Settings: settings, HooksDescription: "test hooks"}

	if err := config.Merge(testPlan(map[string]string{"PreToolUse": "owned"}), func(handler CommandHandler) bool {
		return handler.Command == "owned"
	}); err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 || pre[0] != "invalid" {
		t.Fatalf("malformed event not preserved during merge: %v", pre)
	}

	if err := config.Remove(testPlan(map[string]string{"PreToolUse": "owned"}), func(handler CommandHandler) bool {
		return handler.Command == "owned"
	}); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	pre = settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0] != "invalid" {
		t.Fatalf("malformed event not preserved during remove: %v", pre)
	}
}

func TestConfigRejectsNonObjectHooks(t *testing.T) {
	settings := map[string]any{"hooks": []any{"invalid"}}
	config := Config{Settings: settings, HooksDescription: "test hooks"}

	if _, err := config.HooksMap(); err == nil {
		t.Fatal("HooksMap() error = nil, want non-object hooks error")
	}
	if err := config.Merge(testPlan(map[string]string{"PreToolUse": "owned"}), nil); err == nil {
		t.Fatal("Merge() error = nil, want non-object hooks error")
	}
	if err := config.Remove(testPlan(map[string]string{"PreToolUse": "owned"}), nil); err == nil {
		t.Fatal("Remove() error = nil, want non-object hooks error")
	}
}

func TestConfigRejectsNilSettings(t *testing.T) {
	config := Config{}

	if _, err := config.HooksMap(); err == nil {
		t.Fatal("HooksMap() error = nil, want nil settings error")
	}
	if err := config.Merge(testPlan(map[string]string{"PreToolUse": "owned"}), nil); err == nil {
		t.Fatal("Merge() error = nil, want nil settings error")
	}
	if err := config.Remove(testPlan(map[string]string{"PreToolUse": "owned"}), nil); err == nil {
		t.Fatal("Remove() error = nil, want nil settings error")
	}
}

func TestHasCommand(t *testing.T) {
	hooks := map[string]any{
		"PreToolUse": []any{
			"unparseable",
			map[string]any{"matcher": "", "hooks": []any{
				map[string]any{"type": "command", "command": "owned"},
			}},
		},
	}

	if !HasCommand(hooks, func(handler CommandHandler) bool { return handler.Command == "owned" }) {
		t.Fatal("HasCommand() = false, want true")
	}
	if HasCommand(hooks, func(handler CommandHandler) bool { return handler.Command == "missing" }) {
		t.Fatal("HasCommand(missing) = true, want false")
	}
}

func TestCommandPredicateReceivesArgs(t *testing.T) {
	hooks := map[string]any{
		"PreToolUse": []any{
			map[string]any{"matcher": "", "hooks": []any{
				map[string]any{
					"type":    "command",
					"command": "kontext",
					"args":    []any{"hook", "pre-tool-use"},
				},
				map[string]any{
					"type":    "command",
					"command": "kontext",
					"args":    []any{"other"},
				},
			}},
		},
	}
	matchHook := func(handler CommandHandler) bool {
		return handler.Command == "kontext" &&
			len(handler.Args) == 2 &&
			handler.Args[0] == "hook" &&
			handler.Args[1] == "pre-tool-use"
	}

	if !HasCommand(hooks, matchHook) {
		t.Fatal("HasCommand(args) = false, want true")
	}

	config := Config{Settings: map[string]any{"hooks": hooks}}
	if err := config.Remove(testPlan(map[string]string{"PreToolUse": "unused"}), matchHook); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	pre := config.Settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	handlers := pre[0].(map[string]any)["hooks"].([]any)
	if len(handlers) != 1 {
		t.Fatalf("handlers = %d, want only non-matching args handler", len(handlers))
	}
	kept := handlers[0].(map[string]any)
	if got := kept["args"].([]any)[0]; got != "other" {
		t.Fatalf("kept args = %v, want other handler", kept["args"])
	}
}
