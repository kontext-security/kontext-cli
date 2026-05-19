package managedconfig

const (
	SchemaVersion = "managed-install-v1"
	DefaultMode   = "observe"
	DefaultAgent  = "claude"
)

type Config struct {
	Version        string      `json:"version"`
	OrganizationID string      `json:"organization_id"`
	CloudURL       string      `json:"cloud_url"`
	Mode           string      `json:"mode"`
	Agent          string      `json:"agent"`
	Device         Device      `json:"device,omitempty"`
	Credentials    Credentials `json:"credentials"`
}

type Device struct {
	Label *string `json:"label,omitempty"`
}

type Credentials struct {
	InstallTokenRef string `json:"install_token_ref"`
}
