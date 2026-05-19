package managedconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

type SourceKind string

const (
	SourceFile        SourceKind = "file"
	SourceEnvOverride SourceKind = "env_override"
)

type StateKind string

const (
	StateUnmanaged      StateKind = "unmanaged"
	StateManagedActive  StateKind = "managed_active"
	StateManagedInvalid StateKind = "managed_invalid"
)

type Options struct {
	Path       string
	SourceKind SourceKind
	Now        func() time.Time
}

type State struct {
	Kind       StateKind
	Config     Config
	SourcePath string
	SourceKind SourceKind
	Checksum   string
	LoadedAt   time.Time
	Errors     []ValidationError
}

func DefaultPath() string {
	return "/Library/Application Support/Kontext/managed.json"
}

func Load(ctx context.Context, opts Options) State {
	path := opts.Path
	if path == "" {
		path = DefaultPath()
	}
	sourceKind := opts.SourceKind
	if sourceKind == "" {
		sourceKind = SourceFile
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	loadedAt := now().UTC()
	if err := ctx.Err(); err != nil {
		return invalidState(path, sourceKind, "", loadedAt, ValidationError{Code: "load_failed", Message: err.Error()})
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{Kind: StateUnmanaged, SourcePath: path, SourceKind: sourceKind, LoadedAt: loadedAt}
		}
		return invalidState(path, sourceKind, "", loadedAt, ValidationError{Code: "load_failed", Message: err.Error()})
	}
	checksum := Checksum(data)
	cfg, err := Decode(data)
	if err != nil {
		return invalidState(path, sourceKind, checksum, loadedAt, ValidationError{Code: "invalid_json", Message: err.Error()})
	}
	if errs := Validate(cfg); len(errs) > 0 {
		return State{Kind: StateManagedInvalid, Config: cfg, SourcePath: path, SourceKind: sourceKind, Checksum: checksum, LoadedAt: loadedAt, Errors: errs}
	}
	return State{Kind: StateManagedActive, Config: cfg, SourcePath: path, SourceKind: sourceKind, Checksum: checksum, LoadedAt: loadedAt}
}

func Decode(data []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("unexpected trailing JSON value")
	}
	return cfg, nil
}

func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func invalidState(path string, sourceKind SourceKind, checksum string, loadedAt time.Time, err ValidationError) State {
	return State{
		Kind:       StateManagedInvalid,
		SourcePath: path,
		SourceKind: sourceKind,
		Checksum:   checksum,
		LoadedAt:   loadedAt,
		Errors:     []ValidationError{err},
	}
}
