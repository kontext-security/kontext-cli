package managedconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
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

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Config struct {
	Version        string      `json:"version"`
	OrganizationID string      `json:"organization_id"`
	CloudURL       string      `json:"cloud_url"`
	Mode           string      `json:"mode"`
	Agent          string      `json:"agent"`
	Credentials    Credentials `json:"credentials"`
	Device         Device      `json:"device,omitempty"`
}

type Credentials struct {
	InstallTokenRef TokenRef `json:"install_token_ref"`
}

type TokenSource string

const (
	TokenSourceEnv      TokenSource = "env"
	TokenSourceKeychain TokenSource = "keychain"
)

type TokenRef struct {
	Source TokenSource
	Name   string
}

type Device struct {
	Label string `json:"label,omitempty"`
}

type LoadedConfig struct {
	Config   Config
	Path     string
	Checksum string
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
			return LoadedConfig{}, ErrNotManaged
		}
		return LoadedConfig{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return LoadedConfig{}, err
	}
	digest := sha256.Sum256(data)
	return LoadedConfig{
		Config:   cfg,
		Path:     path,
		Checksum: hex.EncodeToString(digest[:]),
	}, nil
}

func Parse(data []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("unexpected trailing JSON value")
	}
	return normalizeAndValidate(cfg)
}

func ParseTokenRef(value string) (TokenRef, error) {
	value = strings.TrimSpace(value)
	source, name, ok := strings.Cut(value, ":")
	if !ok {
		return TokenRef{}, errors.New("install token ref must use source:name")
	}
	ref := TokenRef{
		Source: TokenSource(strings.TrimSpace(source)),
		Name:   strings.TrimSpace(name),
	}
	if err := validateTokenRef(ref); err != nil {
		return TokenRef{}, err
	}
	return ref, nil
}

func (r TokenRef) String() string {
	if r.Source == "" && r.Name == "" {
		return ""
	}
	return string(r.Source) + ":" + r.Name
}

func (r *TokenRef) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	ref, err := ParseTokenRef(value)
	if err != nil {
		return err
	}
	*r = ref
	return nil
}

func (r TokenRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func ResolveInstallToken(ctx context.Context, ref TokenRef) (string, error) {
	if err := validateTokenRef(ref); err != nil {
		return "", err
	}
	switch ref.Source {
	case TokenSourceEnv:
		token := strings.TrimSpace(os.Getenv(ref.Name))
		if token == "" {
			return "", fmt.Errorf("install token env %s is empty", ref.Name)
		}
		return token, nil
	case TokenSourceKeychain:
		return resolveKeychainInstallToken(ctx, ref.Name)
	default:
		return "", errors.New("install token ref source must be keychain or env")
	}
}

func normalizeAndValidate(cfg Config) (Config, error) {
	cfg.Version = strings.TrimSpace(cfg.Version)
	cfg.OrganizationID = strings.TrimSpace(cfg.OrganizationID)
	cfg.CloudURL = strings.TrimSpace(cfg.CloudURL)
	cfg.Mode = strings.TrimSpace(cfg.Mode)
	cfg.Agent = strings.TrimSpace(cfg.Agent)
	cfg.Credentials.InstallTokenRef.Source = TokenSource(strings.TrimSpace(string(cfg.Credentials.InstallTokenRef.Source)))
	cfg.Credentials.InstallTokenRef.Name = strings.TrimSpace(cfg.Credentials.InstallTokenRef.Name)
	cfg.Device.Label = strings.TrimSpace(cfg.Device.Label)

	if cfg.Version != Version {
		return Config{}, fmt.Errorf("version must be %q", Version)
	}
	if cfg.OrganizationID == "" {
		return Config{}, errors.New("organization_id is required")
	}
	if err := validateCloudURL(cfg.CloudURL); err != nil {
		return Config{}, err
	}
	if cfg.Mode != Mode {
		return Config{}, fmt.Errorf("mode must be %q", Mode)
	}
	if cfg.Agent != Agent {
		return Config{}, fmt.Errorf("agent must be %q", Agent)
	}
	if err := validateTokenRef(cfg.Credentials.InstallTokenRef); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
		if parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) {
			return errors.New("cloud_url must use https unless it is loopback http")
		}
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("cloud_url must include host")
	}
	if parsed.Port() == "" && strings.Contains(parsed.Host, ":") {
		return errors.New("cloud_url must include a valid port")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return errors.New("cloud_url must include a valid port")
		}
	}
	if parsed.User != nil {
		return errors.New("cloud_url must not include userinfo")
	}
	if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return errors.New("cloud_url must not include path")
	}
	if parsed.RawQuery != "" {
		return errors.New("cloud_url must not include query")
	}
	if parsed.Fragment != "" {
		return errors.New("cloud_url must not include fragment")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateTokenRef(ref TokenRef) error {
	switch ref.Source {
	case TokenSourceKeychain, TokenSourceEnv:
	default:
		return errors.New("install token ref source must be keychain or env")
	}
	if ref.Name == "" {
		return errors.New("install token ref name is required")
	}
	if strings.ContainsAny(ref.Name, " \t\r\n:") {
		return errors.New("install token ref name must not contain whitespace or colon")
	}
	if ref.Source == TokenSourceEnv && !envNamePattern.MatchString(ref.Name) {
		return errors.New("env install token ref name must be a valid environment variable name")
	}
	return nil
}

func resolveKeychainInstallToken(ctx context.Context, name string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("keychain install token refs are only supported on macOS")
	}
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", name, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("read install token from keychain: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("install token keychain item %s is empty", name)
	}
	return token, nil
}
