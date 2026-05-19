package managedconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultPath = "/Library/Application Support/Kontext/managed.json"
	EnvPath     = "KONTEXT_MANAGED_CONFIG"

	Version = "managed-install-v1"

	StateUnmanaged      State = "unmanaged"
	StateManagedActive  State = "managed_active"
	StateManagedInvalid State = "managed_invalid"
)

var envTokenRefPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

type State string

type Config struct {
	Version        string      `json:"version"`
	OrganizationID string      `json:"organization_id"`
	CloudURL       string      `json:"cloud_url"`
	Mode           string      `json:"mode"`
	Agent          string      `json:"agent"`
	Device         Device      `json:"device"`
	Credentials    Credentials `json:"credentials"`
}

type Device struct {
	Label    string `json:"label,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type Credentials struct {
	InstallTokenRef string `json:"install_token_ref"`
}

type Source struct {
	Path     string    `json:"path"`
	Checksum string    `json:"checksum,omitempty"`
	LoadedAt time.Time `json:"loaded_at"`
}

type Result struct {
	State  State   `json:"state"`
	Config *Config `json:"config,omitempty"`
	Source Source  `json:"source"`
	Error  string  `json:"error,omitempty"`
}

type ValidationError struct {
	Reason string
}

func (e ValidationError) Error() string {
	return e.Reason
}

func PathFromEnv() string {
	if path := strings.TrimSpace(os.Getenv(EnvPath)); path != "" {
		return path
	}
	return DefaultPath
}

func LoadDefault(now time.Time) Result {
	return Load(PathFromEnv(), now)
}

func Load(path string, now time.Time) Result {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	result := Result{
		State: StateUnmanaged,
		Source: Source{
			Path:     path,
			LoadedAt: now.UTC(),
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result
		}
		result.State = StateManagedInvalid
		result.Error = err.Error()
		return result
	}
	result.Source.Checksum = checksum(data)

	cfg, err := Decode(data)
	if err != nil {
		result.State = StateManagedInvalid
		result.Error = err.Error()
		return result
	}
	result.State = StateManagedActive
	result.Config = &cfg
	return result
}

func Decode(data []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, ValidationError{Reason: err.Error()}
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Config{}, ValidationError{Reason: "unexpected trailing JSON value"}
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Validate(cfg Config) error {
	if cfg.Version != Version {
		return ValidationError{Reason: fmt.Sprintf("version must be %q", Version)}
	}
	if strings.TrimSpace(cfg.OrganizationID) == "" {
		return ValidationError{Reason: "organization_id is required"}
	}
	if err := validateCloudURL(cfg.CloudURL); err != nil {
		return err
	}
	if cfg.Mode != "observe" {
		return ValidationError{Reason: "mode must be observe"}
	}
	if cfg.Agent != "claude" {
		return ValidationError{Reason: "agent must be claude"}
	}
	if err := validateInstallTokenRef(cfg.Credentials.InstallTokenRef); err != nil {
		return err
	}
	return nil
}

func validateCloudURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ValidationError{Reason: "cloud_url is required"}
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ValidationError{Reason: fmt.Sprintf("cloud_url is invalid: %v", err)}
	}
	if parsed.Scheme != "https" {
		return ValidationError{Reason: "cloud_url must use https"}
	}
	if parsed.Host == "" {
		return ValidationError{Reason: "cloud_url must include host"}
	}
	if parsed.User != nil {
		return ValidationError{Reason: "cloud_url must not include user info"}
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return ValidationError{Reason: "cloud_url must not include query or fragment"}
	}
	return nil
}

func validateInstallTokenRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ValidationError{Reason: "credentials.install_token_ref is required"}
	}
	if strings.HasPrefix(ref, "keychain:") {
		if strings.TrimSpace(strings.TrimPrefix(ref, "keychain:")) == "" {
			return ValidationError{Reason: "keychain token ref must include a name"}
		}
		return nil
	}
	if strings.HasPrefix(ref, "env:") {
		name := strings.TrimPrefix(ref, "env:")
		if !envTokenRefPattern.MatchString(name) {
			return ValidationError{Reason: "env token ref must include an uppercase environment variable name"}
		}
		return nil
	}
	return ValidationError{Reason: "credentials.install_token_ref must use keychain:<name> or env:<NAME>"}
}

func RedactTokenRef(ref string) string {
	ref = strings.TrimSpace(ref)
	switch {
	case strings.HasPrefix(ref, "keychain:"):
		return "keychain:<redacted>"
	case strings.HasPrefix(ref, "env:"):
		return "env:<redacted>"
	default:
		return "<redacted>"
	}
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
