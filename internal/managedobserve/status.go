package managedobserve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DaemonStatus is the on-disk breadcrumb a daemon leaves after its socket is
// serving. It is written once at daemon startup; readers must verify the PID is
// alive before trusting it. A stale file from a dead daemon is expected and
// harmless.
// ponytail: PID-reuse false positive possible; add a heartbeat-refreshed updated_at if it ever bites.
type DaemonStatus struct {
	Version   string `json:"version"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
}

// DaemonStatusPath puts the breadcrumb next to the observe database — the one
// directory both the daemon and doctor can always derive.
func DaemonStatusPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "daemon-status.json")
}

func WriteDaemonStatus(dbPath, version string) error {
	return writeJSONBreadcrumb(DaemonStatusPath(dbPath), DaemonStatus{
		Version:   version,
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func LoadDaemonStatus(dbPath string) *DaemonStatus {
	data, err := os.ReadFile(DaemonStatusPath(dbPath))
	if err != nil {
		return nil
	}
	var status DaemonStatus
	// Doctor treats missing, unreadable, and bad status as the same no-status case.
	if err := json.Unmarshal(data, &status); err != nil {
		return nil
	}
	return &status
}
