package credential

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseTemplate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, ".env.kontext")

	content := `
# comment
GITHUB_TOKEN={{kontext:github}}
DATABASE_URL={{kontext:postgres/prod-readonly}}
PLAIN=value
EMPTY=
STRIPE_KEY={{kontext:stripe}}
`

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	entries, err := ParseTemplate(path)
	if err != nil {
		t.Fatalf("ParseTemplate() error = %v", err)
	}

	if got, want := len(entries), 3; got != want {
		t.Fatalf("ParseTemplate() len = %d, want %d", got, want)
	}

	if got, want := entries[0].EnvVar, "GITHUB_TOKEN"; got != want {
		t.Fatalf("entries[0].EnvVar = %q, want %q", got, want)
	}
	if got, want := entries[0].Target(), "github"; got != want {
		t.Fatalf("entries[0].Target() = %q, want %q", got, want)
	}

	if got, want := entries[1].EnvVar, "DATABASE_URL"; got != want {
		t.Fatalf("entries[1].EnvVar = %q, want %q", got, want)
	}
	if got, want := entries[1].Provider, "postgres"; got != want {
		t.Fatalf("entries[1].Provider = %q, want %q", got, want)
	}
	if got, want := entries[1].Resource, "prod-readonly"; got != want {
		t.Fatalf("entries[1].Resource = %q, want %q", got, want)
	}
	if got, want := entries[1].Target(), "postgres/prod-readonly"; got != want {
		t.Fatalf("entries[1].Target() = %q, want %q", got, want)
	}
}
