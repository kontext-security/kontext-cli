package ledger

import "github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"

const (
	SchemaVersion   = "authorization-ledger-v1"
	DefaultEndpoint = "/api/v1/authorization-ledger/batches"
)

type Payload struct {
	SchemaVersion      string                           `json:"schema_version"`
	OrganizationID     string                           `json:"organization_id"`
	InstallationID     string                           `json:"installation_id"`
	BatchID            string                           `json:"batch_id"`
	SentAt             string                           `json:"sent_at"`
	Device             *Device                          `json:"device,omitempty"`
	Sessions           []sqlite.LedgerRecord            `json:"agent_sessions"`
	Actions            []sqlite.LedgerRecord            `json:"authorization_actions"`
	Receipts           []sqlite.LedgerRecord            `json:"authorization_receipts"`
	ReceiptChainAnchor *sqlite.LedgerReceiptChainAnchor `json:"receipt_chain_anchor,omitempty"`
}

type Device struct {
	Label             string `json:"label,omitempty"`
	DeploymentVersion string `json:"deployment_version,omitempty"`
}
