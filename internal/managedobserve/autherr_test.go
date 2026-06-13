package managedobserve

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthErrorRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if got := LoadAuthError(dbPath); got != nil {
		t.Fatalf("LoadAuthError before write = %v, want nil", got)
	}

	if err := WriteAuthError(dbPath, http.StatusUnauthorized); err != nil {
		t.Fatal(err)
	}
	got := LoadAuthError(dbPath)
	if got == nil || got.Status != http.StatusUnauthorized || got.Kind != "auth" || got.At == "" {
		t.Fatalf("LoadAuthError = %+v", got)
	}

	ClearAuthError(dbPath)
	if got := LoadAuthError(dbPath); got != nil {
		t.Fatalf("LoadAuthError after clear = %v, want nil", got)
	}
	// Clearing again is a no-op.
	ClearAuthError(dbPath)
}

func TestStartupErrorRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "guard.db") // dir created on demand

	if err := WriteStartupError(dbPath, "resolve install token: keychain locked"); err != nil {
		t.Fatal(err)
	}
	got := LoadAuthError(dbPath)
	if got == nil || got.Kind != "startup" || got.Message == "" || got.At == "" {
		t.Fatalf("LoadAuthError = %+v", got)
	}

	ClearAuthError(dbPath)
	if LoadAuthError(dbPath) != nil {
		t.Fatal("startup breadcrumb not cleared")
	}
}

func TestLoadAuthErrorToleratesCorruptBreadcrumb(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	if err := os.WriteFile(AuthErrorPath(dbPath), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Doctor reporting must never fail on a corrupt file, and must not turn a
	// local breadcrumb problem into a false revoked-token warning.
	if got := LoadAuthError(dbPath); got == nil || got.Kind != authErrorKindCorrupt || got.Message == "" {
		t.Fatalf("LoadAuthError(corrupt) = %+v", got)
	}
}
