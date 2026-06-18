package managedobserve

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// AuthError is the on-disk breadcrumb a daemon leaves when it cannot
// authenticate: kind "auth" for hosted-ledger rejections (revoked token),
// kind "startup" when the install token could not even be resolved (locked
// keychain, missing item). The daemon's stderr goes to a log file nobody
// watches, so `kontext doctor` reads this file to give the user the actual
// next step.
type AuthError struct {
	Kind    string `json:"kind"`
	Status  int    `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
	At      string `json:"at"`
}

const authErrorKindCorrupt = "corrupt"

// AuthErrorPath puts the breadcrumb next to the observe database — the one
// directory both the daemon and doctor can always derive.
func AuthErrorPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "last-auth-error.json")
}

func WriteAuthError(dbPath string, status int) error {
	return writeBreadcrumb(dbPath, AuthError{Kind: "auth", Status: status})
}

// WriteStartupError records that the daemon exited before streaming — e.g.
// the keychain item was unreadable under launchd. Without it, doctor can only
// say "daemon: not running" with no cause.
func WriteStartupError(dbPath string, message string) error {
	return writeBreadcrumb(dbPath, AuthError{Kind: "startup", Message: message})
}

func writeBreadcrumb(dbPath string, breadcrumb AuthError) error {
	breadcrumb.At = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(breadcrumb)
	if err != nil {
		return err
	}
	path := AuthErrorPath(dbPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(path), ".last-auth-error-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func ClearAuthError(dbPath string) error {
	err := os.Remove(AuthErrorPath(dbPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// LoadAuthError returns the breadcrumb, or nil when none exists. Unreadable or
// corrupt files are returned as a distinct diagnostic kind so doctor never
// turns a local breadcrumb problem into a false revoked-token warning.
func LoadAuthError(dbPath string) *AuthError {
	data, err := os.ReadFile(AuthErrorPath(dbPath))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return &AuthError{Kind: authErrorKindCorrupt, Message: err.Error()}
		}
		return nil
	}
	var authErr AuthError
	if err := json.Unmarshal(data, &authErr); err != nil {
		return &AuthError{Kind: authErrorKindCorrupt, Message: err.Error()}
	}
	return &authErr
}
