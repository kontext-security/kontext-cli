package agenthooks

import "testing"

func TestSplitCommand(t *testing.T) {
	fields, ok := SplitCommand(`'/Users/o'\''brien/bin/kontext' hook 'pre-tool-use'`)
	if !ok {
		t.Fatal("SplitCommand() ok = false, want true")
	}
	want := []string{"/Users/o'brien/bin/kontext", "hook", "pre-tool-use"}
	if len(fields) != len(want) {
		t.Fatalf("fields = %v, want %v", fields, want)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("fields = %v, want %v", fields, want)
		}
	}

	if _, ok := SplitCommand(`'/usr/local/bin/kontext hook`); ok {
		t.Fatal("SplitCommand(unterminated) ok = true, want false")
	}

	fields, ok = SplitCommand(`"/tmp/kon\text" hook pre-tool-use`)
	if !ok {
		t.Fatal("SplitCommand(backslash) ok = false, want true")
	}
	if fields[0] != `/tmp/kon\text` {
		t.Fatalf("first field = %q, want preserved backslash", fields[0])
	}
}
