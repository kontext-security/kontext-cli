package installation

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultPath = "/Library/Application Support/Kontext/installation.json"
	EnvPath     = "KONTEXT_INSTALLATION_STATE"
)

var ErrNotFound = errors.New("installation state not found")

type State struct {
	InstallationID string `json:"installation_id"`
}

func PathFromEnv() string {
	if path := strings.TrimSpace(os.Getenv(EnvPath)); path != "" {
		return path
	}
	return DefaultPath
}

func Load() (State, error) {
	return LoadFile(PathFromEnv())
}

func LoadFile(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, ErrNotFound
		}
		return State{}, fmt.Errorf("read installation state: %w", err)
	}
	state, err := parse(data)
	if err != nil {
		return State{}, err
	}
	return state, nil
}

func Ensure() (State, error) {
	return EnsureFile(PathFromEnv())
}

func EnsureFile(path string) (State, error) {
	state, err := LoadFile(path)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return State{}, err
	}

	candidate := State{InstallationID: newInstallationID()}
	if err := createFile(path, candidate); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadFile(path)
		}
		return State{}, err
	}
	return LoadFile(path)
}

func parse(data []byte) (State, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var state State
	if err := dec.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode installation state: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return State{}, errors.New("decode installation state: trailing data")
	}
	if !validInstallationID(state.InstallationID) {
		return State{}, errors.New("installation_id must use ins_ format")
	}
	return state, nil
}

func createFile(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create installation state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal installation state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".installation-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary installation state: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write installation state: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync installation state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close installation state: %w", err)
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return fmt.Errorf("chmod installation state: %w", err)
	}
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist
		}
		return fmt.Errorf("publish installation state: %w", err)
	}
	return nil
}

func validInstallationID(id string) bool {
	if !strings.HasPrefix(id, "ins_") {
		return false
	}
	return len(id) > len("ins_")
}

func newInstallationID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("generate installation id: %v", err))
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	return "ins_" + strings.ToLower(encoded)
}
