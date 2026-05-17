package modelsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
)

type Snapshot struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Store struct {
	root     string
	validate func(*markov.Model) error
}

func NewWithValidator(root string, validate func(*markov.Model) error) *Store {
	return &Store{root: root, validate: validate}
}

func (s *Store) ActivateFromFile(path string) (Snapshot, error) {
	if strings.TrimSpace(path) == "" {
		return Snapshot{}, fmt.Errorf("model path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	return s.activate(data)
}

func (s *Store) ActivateBytes(data []byte) (Snapshot, error) {
	if len(data) == 0 {
		return Snapshot{}, fmt.Errorf("model data is required")
	}
	return s.activate(data)
}

func (s *Store) activate(data []byte) (Snapshot, error) {
	model, err := markov.ReadModelJSON(bytes.NewReader(data))
	if err != nil {
		return Snapshot{}, fmt.Errorf("validate model snapshot: %w", err)
	}
	if s.validate != nil {
		if err := s.validate(model); err != nil {
			return Snapshot{}, fmt.Errorf("validate model snapshot: %w", err)
		}
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	active, activeErr := s.active()
	if activeErr == nil && active.SHA256 == hash {
		return active, nil
	} else if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return Snapshot{}, activeErr
	}

	now := time.Now().UTC()
	id := now.Format("20060102T150405.000000000Z") + "-" + hash[:12]
	snapshotDir := filepath.Join(s.root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return Snapshot{}, err
	}
	modelPath := filepath.Join(snapshotDir, id+".json")
	if err := writeFileAtomic(modelPath, data, 0o600); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		ID:     id,
		Path:   modelPath,
		SHA256: hash,
	}
	if err := s.writeActive(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) active() (Snapshot, error) {
	data, err := os.ReadFile(s.activePath())
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, os.ErrNotExist
	}
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.ID == "" || snapshot.Path == "" {
		return Snapshot{}, fmt.Errorf("active model snapshot is invalid")
	}
	return snapshot, nil
}

func (s *Store) writeActive(snapshot Snapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(s.activePath(), data, 0o600)
}

func (s *Store) activePath() string {
	return filepath.Join(s.root, "active.json")
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
