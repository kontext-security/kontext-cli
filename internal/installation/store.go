package installation

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultPath = "/Library/Application Support/Kontext/installation.json"
	EnvPath     = "KONTEXT_INSTALLATION_STATE"

	Version = "installation-v1"
)

var installationIDPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{22,}$`)

type Record struct {
	Version        string    `json:"version"`
	InstallationID string    `json:"installation_id"`
	CreatedAt      time.Time `json:"created_at"`
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

func LoadDefault() (Record, bool, error) {
	return Load(PathFromEnv())
}

func EnsureDefault(now time.Time) (Record, error) {
	return Ensure(PathFromEnv(), now)
}

func Load(path string) (Record, bool, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	record, err := Decode(data)
	if err != nil {
		return Record{}, true, err
	}
	return record, true, nil
}

func Ensure(path string, now time.Time) (Record, error) {
	record, exists, err := Load(path)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return record, nil
	}

	id, err := NewID()
	if err != nil {
		return Record{}, err
	}
	record = Record{
		Version:        Version,
		InstallationID: id,
		CreatedAt:      now.UTC(),
	}
	if err := Write(path, record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func NewID() (string, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate installation id: %w", err)
	}
	return "ins_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func Decode(data []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var record Record
	if err := dec.Decode(&record); err != nil {
		return Record{}, ValidationError{Reason: err.Error()}
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Record{}, ValidationError{Reason: "unexpected trailing JSON value"}
	}
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Validate(record Record) error {
	if record.Version != Version {
		return ValidationError{Reason: fmt.Sprintf("version must be %q", Version)}
	}
	if !installationIDPattern.MatchString(record.InstallationID) {
		return ValidationError{Reason: "installation_id is invalid"}
	}
	if record.CreatedAt.IsZero() {
		return ValidationError{Reason: "created_at is required"}
	}
	return nil
}

func Write(path string, record Record) error {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	if err := Validate(record); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data)
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".installation-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
