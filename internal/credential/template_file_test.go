package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureManagedTemplateCreatesNewFileWithDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	result, err := EnsureManagedTemplate(path, []ManagedProvider{
		{EnvVar: "GITHUB_TOKEN", Placeholder: "{{kontext:github}}", SeedOnFirstRun: true},
		{EnvVar: "LINEAR_API_KEY", Placeholder: "{{kontext:linear}}", SeedOnFirstRun: true},
		{EnvVar: "SLACK_TOKEN", Placeholder: "{{kontext:slack}}", SeedOnFirstRun: false},
	})
	if err != nil {
		t.Fatalf("EnsureManagedTemplate() error = %v", err)
	}
	if !result.Created {
		t.Fatal("EnsureManagedTemplate() Created = false, want true")
	}
	if got, want := len(result.Added), 2; got != want {
		t.Fatalf("EnsureManagedTemplate() added len = %d, want %d", got, want)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read created file: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "GITHUB_TOKEN={{kontext:github}}") {
		t.Fatalf("created file missing github placeholder: %q", text)
	}
	if !strings.Contains(text, "LINEAR_API_KEY={{kontext:linear}}") {
		t.Fatalf("created file missing linear placeholder: %q", text)
	}
	if strings.Contains(text, "SLACK_TOKEN={{kontext:slack}}") {
		t.Fatalf("created file unexpectedly seeded slack placeholder: %q", text)
	}
}

func TestEnsureManagedTemplateAppendsMissingManagedEntries(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN={{kontext:github}}\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	result, err := EnsureManagedTemplate(path, []ManagedProvider{
		{EnvVar: "GITHUB_TOKEN", Placeholder: "{{kontext:github}}", SeedOnFirstRun: true},
		{EnvVar: "LINEAR_API_KEY", Placeholder: "{{kontext:linear}}", SeedOnFirstRun: true},
	})
	if err != nil {
		t.Fatalf("EnsureManagedTemplate() error = %v", err)
	}
	if !result.Updated {
		t.Fatal("EnsureManagedTemplate() Updated = false, want true")
	}
	if got, want := len(result.Added), 1; got != want {
		t.Fatalf("EnsureManagedTemplate() added len = %d, want %d", got, want)
	}
	if got := result.Added[0].EnvVar; got != "LINEAR_API_KEY" {
		t.Fatalf("EnsureManagedTemplate() added env var = %q, want %q", got, "LINEAR_API_KEY")
	}
}

func TestEnsureManagedTemplateReportsCollisionWithoutOverwriting(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("SLACK_TOKEN=xoxb-literal\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	result, err := EnsureManagedTemplate(path, []ManagedProvider{
		{EnvVar: "SLACK_TOKEN", Placeholder: "{{kontext:slack}}", SeedOnFirstRun: false},
	})
	if err != nil {
		t.Fatalf("EnsureManagedTemplate() error = %v", err)
	}
	if got, want := len(result.CollisionSkipped), 1; got != want {
		t.Fatalf("EnsureManagedTemplate() collision len = %d, want %d", got, want)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	if got := string(content); got != "SLACK_TOKEN=xoxb-literal\n" {
		t.Fatalf("template content = %q, want literal value preserved", got)
	}
}

func TestEnsureManagedTemplateDoesNotReportCollisionForQuotedManagedPlaceholder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN=\"{{kontext:github}}\"\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	result, err := EnsureManagedTemplate(path, []ManagedProvider{
		{EnvVar: "GITHUB_TOKEN", Placeholder: "{{kontext:github}}", SeedOnFirstRun: true},
	})
	if err != nil {
		t.Fatalf("EnsureManagedTemplate() error = %v", err)
	}
	if got := len(result.CollisionSkipped); got != 0 {
		t.Fatalf("collision len = %d, want 0", got)
	}
	if result.Updated {
		t.Fatal("EnsureManagedTemplate() Updated = true, want false")
	}
}

func TestEnsureManagedTemplateDoesNotReportCollisionForCommentedManagedPlaceholder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN={{kontext:github}} # personal account\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	result, err := EnsureManagedTemplate(path, []ManagedProvider{
		{EnvVar: "GITHUB_TOKEN", Placeholder: "{{kontext:github}}", SeedOnFirstRun: true},
	})
	if err != nil {
		t.Fatalf("EnsureManagedTemplate() error = %v", err)
	}
	if got := len(result.CollisionSkipped); got != 0 {
		t.Fatalf("collision len = %d, want 0", got)
	}
	if result.Updated {
		t.Fatal("EnsureManagedTemplate() Updated = true, want false")
	}
}

func TestEnsureManagedTemplateAppendsNonSeededManagedProvidersOnExistingFiles(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN={{kontext:github}}\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	result, err := EnsureManagedTemplate(path, []ManagedProvider{
		{EnvVar: "GITHUB_TOKEN", Placeholder: "{{kontext:github}}", SeedOnFirstRun: true},
		{EnvVar: "SLACK_TOKEN", Placeholder: "{{kontext:slack}}", SeedOnFirstRun: false},
	})
	if err != nil {
		t.Fatalf("EnsureManagedTemplate() error = %v", err)
	}
	if !result.Updated {
		t.Fatal("EnsureManagedTemplate() Updated = false, want true")
	}
	if got, want := len(result.Added), 1; got != want {
		t.Fatalf("EnsureManagedTemplate() added len = %d, want %d", got, want)
	}
	if got := result.Added[0].EnvVar; got != "SLACK_TOKEN" {
		t.Fatalf("EnsureManagedTemplate() added env var = %q, want %q", got, "SLACK_TOKEN")
	}
}

func TestLoadTemplateFileMarksDuplicateKeysUnsafeForMutation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN={{kontext:github}}\nGITHUB_TOKEN=literal\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	doc, err := LoadTemplateFile(path)
	if err != nil {
		t.Fatalf("LoadTemplateFile() error = %v", err)
	}
	if doc.SafeToMutate {
		t.Fatal("LoadTemplateFile() SafeToMutate = true, want false")
	}
	if !strings.Contains(doc.MutationWarning, "declared more than once") {
		t.Fatalf("mutation warning = %q, want duplicate-key warning", doc.MutationWarning)
	}
	if got := doc.ExistingValues["GITHUB_TOKEN"]; got != "literal" {
		t.Fatalf("existing value = %q, want last duplicate assignment", got)
	}
	if got := len(doc.Entries); got != 0 {
		t.Fatalf("entries len = %d, want 0 after later literal override", got)
	}
}

func TestLoadTemplateFilePreservesLastDuplicatePlaceholderAssignment(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN=literal\nGITHUB_TOKEN={{kontext:github}}\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	doc, err := LoadTemplateFile(path)
	if err != nil {
		t.Fatalf("LoadTemplateFile() error = %v", err)
	}
	if doc.SafeToMutate {
		t.Fatal("LoadTemplateFile() SafeToMutate = true, want false")
	}
	if got := doc.ExistingValues["GITHUB_TOKEN"]; got != "{{kontext:github}}" {
		t.Fatalf("existing value = %q, want last duplicate assignment", got)
	}
	if got, want := len(doc.Entries), 1; got != want {
		t.Fatalf("entries len = %d, want %d", got, want)
	}
	if got := doc.Entries[0].Raw; got != "{{kontext:github}}" {
		t.Fatalf("entry raw = %q, want %q", got, "{{kontext:github}}")
	}
}

func TestLoadTemplateFileCollectsInvalidPlaceholders(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("BROKEN={{kontext:}}\nGITHUB_TOKEN={{kontext:github}}\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	doc, err := LoadTemplateFile(path)
	if err != nil {
		t.Fatalf("LoadTemplateFile() error = %v", err)
	}
	if got, want := len(doc.InvalidPlaceholders), 1; got != want {
		t.Fatalf("invalid placeholders len = %d, want %d", got, want)
	}
	if got := doc.InvalidPlaceholders[0].EnvVar; got != "BROKEN" {
		t.Fatalf("invalid placeholder env var = %q, want %q", got, "BROKEN")
	}
	if got, want := len(doc.Entries), 1; got != want {
		t.Fatalf("valid entries len = %d, want %d", got, want)
	}
}

func TestLoadTemplateFileAcceptsQuotedPlaceholders(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN=\"{{kontext:github}}\"\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	doc, err := LoadTemplateFile(path)
	if err != nil {
		t.Fatalf("LoadTemplateFile() error = %v", err)
	}
	if got, want := len(doc.Entries), 1; got != want {
		t.Fatalf("entries len = %d, want %d", got, want)
	}
	if got := doc.Entries[0].Raw; got != "{{kontext:github}}" {
		t.Fatalf("entry raw = %q, want %q", got, "{{kontext:github}}")
	}
}

func TestLoadTemplateFileAcceptsPlaceholdersWithInlineComments(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env.kontext")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN={{kontext:github}} # personal account\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	doc, err := LoadTemplateFile(path)
	if err != nil {
		t.Fatalf("LoadTemplateFile() error = %v", err)
	}
	if got, want := len(doc.Entries), 1; got != want {
		t.Fatalf("entries len = %d, want %d", got, want)
	}
	if got := doc.Entries[0].Raw; got != "{{kontext:github}}" {
		t.Fatalf("entry raw = %q, want %q", got, "{{kontext:github}}")
	}
}
