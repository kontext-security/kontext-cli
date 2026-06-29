package agenthooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReadJSONFile parses a hook settings file into a generic map so unknown keys
// survive a read-merge-write round trip. A missing file is an empty map.
func ReadJSONFile(path, description string) (map[string]any, error) {
	settings := map[string]any{}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("parse %s: %w", description, err)
	}
	return settings, nil
}

// WriteJSONFile writes a hook settings map atomically, preserving existing
// permission bits. If path is a symlink, the symlink is left in place and its
// resolved target is rewritten.
func WriteJSONFile(path string, settings map[string]any) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return WriteRawFile(path, append(data, '\n'))
}

// WriteRawFile writes data to path atomically (temp file + rename), preserving
// the existing file's permission bits (new files are 0600). If path is a
// symlink, the symlink is left in place and its resolved target is rewritten.
// The bytes are written verbatim, so the caller owns trailing-newline handling.
func WriteRawFile(path string, data []byte) error {
	writePath := path
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		writePath = target
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	mode := fs.FileMode(0o600)
	if info, err := os.Stat(writePath); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(writePath), ".settings-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, writePath)
}

// BackupFile copies path aside with a timestamped suffix and matching
// permissions. Missing files are a no-op.
func BackupFile(path, label string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	backupPathPrefix := fmt.Sprintf("%s.%s-backup-%s", path, label, time.Now().UTC().Format("20060102T150405.000000000Z"))
	var file *os.File
	for attempt := 0; attempt < 100; attempt++ {
		backupPath := backupPathPrefix
		if attempt > 0 {
			backupPath = fmt.Sprintf("%s-%d", backupPathPrefix, attempt)
		}
		file, err = os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if file == nil {
		return fmt.Errorf("create backup for %s: too many timestamp collisions", path)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// ShellQuote quotes one shell token for hook command strings.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
