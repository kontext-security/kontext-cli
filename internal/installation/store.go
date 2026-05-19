package installation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	fileMode = 0o600
	dirMode  = 0o755
)

type Option func(*options)

type options struct {
	now func() time.Time
}

func WithClock(now func() time.Time) Option {
	return func(opts *options) {
		if now != nil {
			opts.now = now
		}
	}
}

func Load(path string) (Installation, error) {
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Installation{}, err
	}
	return decode(data)
}

func Ensure(ctx context.Context, path string, opts ...Option) (Installation, error) {
	if path == "" {
		path = DefaultPath()
	}
	if err := ctx.Err(); err != nil {
		return Installation{}, err
	}
	unlock, err := lockFileAt(ctx, path+".lock")
	if err != nil {
		return Installation{}, err
	}
	defer unlock()

	existing, err := Load(path)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Installation{}, err
	}
	cfg := options{now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(&cfg)
	}
	id, err := newInstallationID()
	if err != nil {
		return Installation{}, err
	}
	inst := Installation{
		Version:        SchemaVersion,
		InstallationID: id,
		CreatedAt:      cfg.now().UTC(),
		CreatedBy:      "kontext-cli",
	}
	data, err := encode(inst)
	if err != nil {
		return Installation{}, err
	}
	if err := writeFileAtomic(path, data, fileMode); err != nil {
		return Installation{}, err
	}
	return inst, nil
}

func decode(data []byte) (Installation, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var inst Installation
	if err := decoder.Decode(&inst); err != nil {
		return Installation{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Installation{}, errors.New("unexpected trailing JSON value")
	}
	if err := validate(inst); err != nil {
		return Installation{}, err
	}
	return inst, nil
}

func encode(inst Installation) ([]byte, error) {
	if err := validate(inst); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(inst, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func validate(inst Installation) error {
	if inst.Version != SchemaVersion {
		return fmt.Errorf("version must be %q", SchemaVersion)
	}
	if !strings.HasPrefix(inst.InstallationID, "ins_") || len(inst.InstallationID) < 12 {
		return errors.New("installation_id must use ins_ prefix")
	}
	if inst.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if strings.TrimSpace(inst.CreatedBy) == "" {
		return errors.New("created_by is required")
	}
	return nil
}

func newInstallationID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "ins_" + hex.EncodeToString(data[:]), nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func waitForLockRetry(ctx context.Context) error {
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
