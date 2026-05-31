package managedstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/ledger"
)

const (
	DefaultBatchLimit = 500
	DefaultInterval   = 10 * time.Second

	envStatePath = "KONTEXT_MANAGED_STREAM_STATE"
	envInterval  = "KONTEXT_MANAGED_STREAM_INTERVAL"
)

type Options struct {
	DBPath            string
	StatePath         string
	CloudURL          string
	OrganizationID    string
	InstallationID    string
	InstallToken      string
	DeviceLabel       string
	DeploymentVersion func() string
	Interval          time.Duration
	BatchLimit        int
	HTTPClient        *http.Client
	Diagnostic        diagnostic.Logger
}

type State struct {
	UpdatedAfter *time.Time
	ActionID     string
}

func Run(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultIntervalFromEnv()
	}

	if err := Flush(ctx, opts); err != nil {
		opts.Diagnostic.Printf("managed stream flush: %v\n", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := Flush(ctx, opts); err != nil {
				opts.Diagnostic.Printf("managed stream flush: %v\n", err)
			}
		}
	}
}

func Flush(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	store, err := sqlite.OpenStore(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	statePath := opts.StatePath
	if statePath == "" {
		statePath = DefaultStatePathForDB(opts.DBPath)
	}
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}

	limit := opts.BatchLimit
	if limit <= 0 {
		limit = DefaultBatchLimit
	}
	batch, err := store.LedgerBatch(ctx, sqlite.LedgerExportOptions{
		UpdatedAfter:   state.UpdatedAfter,
		UpdatedAfterID: state.ActionID,
		Limit:          limit,
	})
	if err != nil {
		return err
	}
	if len(batch.Actions) == 0 {
		return nil
	}

	payload := ledger.Payload{
		SchemaVersion:      ledger.SchemaVersion,
		OrganizationID:     opts.OrganizationID,
		InstallationID:     opts.InstallationID,
		BatchID:            "batch_" + uuid.NewString(),
		SentAt:             time.Now().UTC().Format(time.RFC3339Nano),
		Sessions:           batch.Sessions,
		Actions:            batch.Actions,
		Receipts:           batch.Receipts,
		ReceiptChainAnchor: batch.ReceiptChainAnchor,
	}
	// Resolve the deployment version per flush so an in-place package upgrade
	// is reflected without restarting the daemon.
	label := strings.TrimSpace(opts.DeviceLabel)
	deploymentVersion := ""
	if opts.DeploymentVersion != nil {
		deploymentVersion = strings.TrimSpace(opts.DeploymentVersion())
	}
	if label != "" || deploymentVersion != "" {
		payload.Device = &ledger.Device{Label: label, DeploymentVersion: deploymentVersion}
	}
	if err := post(ctx, opts, payload); err != nil {
		return err
	}

	if batch.Cursor != nil {
		updatedAfter := batch.Cursor.UpdatedAt.UTC()
		return SaveState(statePath, State{
			UpdatedAfter: &updatedAfter,
			ActionID:     batch.Cursor.ActionID,
		})
	}
	return nil
}

func post(ctx context.Context, opts Options, payload ledger.Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint, err := endpointURL(opts.CloudURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(opts.InstallToken))

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("hosted ledger ingest failed: status %d", resp.StatusCode)
	}
	return nil
}

func endpointURL(cloudURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cloudURL))
	if err != nil {
		return "", err
	}
	parsed.Path = ledger.DefaultEndpoint
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func DefaultStatePath() string {
	if path := strings.TrimSpace(os.Getenv(envStatePath)); path != "" {
		return path
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "Kontext", "managed-observe", "stream-state.json")
	}
	return filepath.Join("managed-observe", "stream-state.json")
}

func DefaultStatePathForDB(dbPath string) string {
	if path := strings.TrimSpace(os.Getenv(envStatePath)); path != "" {
		return path
	}
	if dbPath = strings.TrimSpace(dbPath); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "stream-state.json")
	}
	return DefaultStatePath()
}

func DefaultIntervalFromEnv() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envInterval)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultInterval
}

func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}

	type diskState struct {
		UpdatedAfter string `json:"updated_after,omitempty"`
		ActionID     string `json:"action_id,omitempty"`
	}

	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}

	updatedAfter := strings.TrimSpace(state.UpdatedAfter)
	actionID := strings.TrimSpace(state.ActionID)

	var parsedUpdatedAfter *time.Time
	if updatedAfter != "" {
		parsed, err := time.Parse(time.RFC3339Nano, updatedAfter)
		if err != nil {
			return State{}, fmt.Errorf("parse managed stream state updated_after: %w", err)
		}
		parsedUpdatedAfter = &parsed
	}

	return State{
		UpdatedAfter: parsedUpdatedAfter,
		ActionID:     actionID,
	}, nil
}

func SaveState(path string, state State) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	type diskState struct {
		UpdatedAfter string `json:"updated_after,omitempty"`
		ActionID     string `json:"action_id,omitempty"`
	}

	updatedAfter := ""
	if state.UpdatedAfter != nil {
		updatedAfter = state.UpdatedAfter.UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(diskState{
		UpdatedAfter: updatedAfter,
		ActionID:     strings.TrimSpace(state.ActionID),
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(path), ".stream-state-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	closed := false
	cleanup := true
	defer func() {
		if cleanup {
			var cleanupErr error
			if !closed {
				cleanupErr = errors.Join(cleanupErr, temp.Close())
			}
			cleanupErr = errors.Join(cleanupErr, os.Remove(tempPath))
			if cleanupErr == nil {
				return
			}
			if err == nil {
				err = cleanupErr
				return
			}
			err = errors.Join(err, cleanupErr)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	closeErr := temp.Close()
	closed = true
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func validateOptions(opts Options) error {
	if strings.TrimSpace(opts.DBPath) == "" {
		return errors.New("managed stream requires db path")
	}
	if strings.TrimSpace(opts.CloudURL) == "" {
		return errors.New("managed stream requires cloud url")
	}
	if strings.TrimSpace(opts.OrganizationID) == "" {
		return errors.New("managed stream requires organization id")
	}
	if strings.TrimSpace(opts.InstallationID) == "" {
		return errors.New("managed stream requires installation id")
	}
	if strings.TrimSpace(opts.InstallToken) == "" {
		return errors.New("managed stream requires install token")
	}
	return nil
}
