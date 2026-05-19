package installation

import "time"

const SchemaVersion = "managed-installation-v1"

type Installation struct {
	Version        string    `json:"version"`
	InstallationID string    `json:"installation_id"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

func DefaultPath() string {
	return "/Library/Application Support/Kontext/installation.json"
}
