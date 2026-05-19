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
	"strings"
)

const (
	Version = "managed-install-v1"
	Mode    = "observe"
	Agent   = "claude"

	DefaultPath = "/Library/Application Support/Kontext/managed.json"
	EnvPath     = "KONTEXT_MANAGED_CONFIG"
)

var ErrNotManaged = errors.New("managed config not found")

type Config struct {
	Version        string
	OrganizationID string
	CloudURL       string
	Mode           string
	Agent          string
	Credentials    Credentials
	Device         Device
}

type Credentials struct {
	InstallTokenRef TokenRef
}

type Device struct {
	Label string
}

type TokenRef struct {
	Source string
	Name   string
}

type LoadedConfig struct {
	Config   Config
	Path     string
	Checksum string
}

type rawConfig struct {
	Version        string         `json:"version"`
	OrganizationID string         `json:"organization_id"`
	CloudURL       string         `json:"cloud_url"`
	Mode           string         `json:"mode"`
	Agent          string         `json:"agent"`
	Credentials    rawCredentials `json:"credentials"`
	Device         *rawDevice     `json:"device,omitempty"`
}

type rawCredentials struct {
	InstallTokenRef string `json:"install_token_ref"`
}

type rawDevice struct {
	Label string `json:"label,omitempty"`
}

func PathFromEnv() string {
	if path := strings.TrimSpace(os.Getenv(EnvPath)); path != "" {
		return path
	}
	return DefaultPath
}

func Load() (LoadedConfig, error) {
	return LoadFile(PathFromEnv())
}

func LoadFile(path string) (LoadedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LoadedConfig{Path: path}, ErrNotManaged
		}
		return LoadedConfig{Path: path}, fmt.Errorf("read managed config: %w", err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return LoadedConfig{Path: path, Checksum: checksum(data)}, err
	}
	return LoadedConfig{Config: cfg, Path: path, Checksum: checksum(data)}, nil
}

func Parse(data []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var raw rawConfig
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode managed config: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return Config{}, errors.New("decode managed config: trailing data")
	}

	cfg := Config{
		Version:        strings.TrimSpace(raw.Version),
		OrganizationID: strings.TrimSpace(raw.OrganizationID),
		CloudURL:       strings.TrimSpace(raw.CloudURL),
		Mode:           strings.TrimSpace(raw.Mode),
		Agent:          strings.TrimSpace(raw.Agent),
		Device:         Device{},
	}
	if raw.Device != nil {
		cfg.Device.Label = strings.TrimSpace(raw.Device.Label)
	}

	ref, err := ParseTokenRef(raw.Credentials.InstallTokenRef)
	if err != nil {
		return Config{}, err
	}
	cfg.Credentials.InstallTokenRef = ref

	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Validate(cfg Config) error {
	if cfg.Version != Version {
		return fmt.Errorf("version must be %q", Version)
	}
	if cfg.OrganizationID == "" {
		return errors.New("organization_id is required")
	}
	if err := validateCloudURL(cfg.CloudURL); err != nil {
		return err
	}
	if cfg.Mode != Mode {
		return fmt.Errorf("mode must be %q", Mode)
	}
	if cfg.Agent != Agent {
		return fmt.Errorf("agent must be %q", Agent)
	}
	if cfg.Credentials.InstallTokenRef.Source == "" || cfg.Credentials.InstallTokenRef.Name == "" {
		return errors.New("credentials.install_token_ref is required")
	}
	return nil
}

func ParseTokenRef(value string) (TokenRef, error) {
	value = strings.TrimSpace(value)
	source, name, ok := strings.Cut(value, ":")
	if !ok {
		return TokenRef{}, errors.New("credentials.install_token_ref must use keychain:<name> or env:<NAME>")
	}
	source = strings.TrimSpace(source)
	name = strings.TrimSpace(name)
	if name == "" {
		return TokenRef{}, errors.New("credentials.install_token_ref name is required")
	}
	if strings.ContainsAny(name, " \t\r\n:") {
		return TokenRef{}, errors.New("credentials.install_token_ref name must not contain whitespace or colon")
	}
	switch source {
	case "keychain", "env":
		return TokenRef{Source: source, Name: name}, nil
	default:
		return TokenRef{}, errors.New("credentials.install_token_ref must use keychain:<name> or env:<NAME>")
	}
}

func (r TokenRef) String() string {
	if r.Source == "" || r.Name == "" {
		return ""
	}
	return r.Source + ":" + r.Name
}

func validateCloudURL(value string) error {
	if value == "" {
		return errors.New("cloud_url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("cloud_url is invalid: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("cloud_url must use https")
	}
	if parsed.Host == "" {
		return errors.New("cloud_url host is required")
	}
	if parsed.User != nil {
		return errors.New("cloud_url must not include userinfo")
	}
	if parsed.RawQuery != "" {
		return errors.New("cloud_url must not include query")
	}
	if parsed.Fragment != "" {
		return errors.New("cloud_url must not include fragment")
	}
	return nil
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
