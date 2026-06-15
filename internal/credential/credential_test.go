package credential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplateFileEntries(t *testing.T) {
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

	doc, err := LoadTemplateFile(path)
	if err != nil {
		t.Fatalf("LoadTemplateFile() error = %v", err)
	}
	entries := doc.Entries

	if got, want := len(entries), 3; got != want {
		t.Fatalf("LoadTemplateFile() entries len = %d, want %d", got, want)
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

func TestProviderFuncResolvesCredential(t *testing.T) {
	t.Parallel()

	provider := ProviderFunc(func(_ context.Context, entry Entry) (Resolved, error) {
		return Resolved{Entry: entry, Value: "token"}, nil
	})

	resolved, err := provider.ResolveCredential(context.Background(), Entry{
		EnvVar:   "GITHUB_TOKEN",
		Provider: "github",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EnvVar != "GITHUB_TOKEN" || resolved.Value != "token" {
		t.Fatalf("resolved = %+v", resolved)
	}
}

func TestNoopProviderReportsUnavailable(t *testing.T) {
	t.Parallel()

	_, err := NoopProvider{}.ResolveCredential(context.Background(), Entry{
		EnvVar:   "GITHUB_TOKEN",
		Provider: "github",
	})
	if !errors.Is(err, ErrNoopProvider) {
		t.Fatalf("err = %v, want ErrNoopProvider", err)
	}
}
