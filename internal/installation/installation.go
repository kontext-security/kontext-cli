package installation

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const SchemaVersion = "managed-installation-v1"

type Installation struct {
	Version        string    `json:"version"`
	InstallationID string    `json:"installation_id"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

func DefaultPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Kontext/installation.json"
	case "windows":
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "Kontext", "installation.json")
		}
		return `C:\ProgramData\Kontext\installation.json`
	default:
		return "/var/lib/kontext/installation.json"
	}
}
