package run

import (
	"reflect"
	"testing"
)

func TestFilterArgs(t *testing.T) {
	t.Parallel()

	args := []string{
		"--settings", "user-settings.json",
		"--dangerously-skip-permissions",
		"--setting-sources=local",
		"--allowed",
		"value",
		"--bare",
		"prompt",
	}

	got := filterArgs(args)
	want := []string{"--allowed", "value", "prompt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterArgs() = %#v, want %#v", got, want)
	}
}
