package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

const (
	defaultAACBin = "aac"
)

type bitwardenCredentialResolver struct{}

type bitwardenConnectResponse struct {
	Success      bool   `json:"success"`
	Domain       string `json:"domain"`
	CredentialID string `json:"credential_id"`
	Credential   struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
		URI      string `json:"uri"`
		Notes    string `json:"notes"`
		ID       string `json:"id"`
	} `json:"credential"`
}

type bitwardenResolutionError struct {
	Entry   credential.Entry
	Message string
}

func (e *bitwardenResolutionError) Error() string {
	return e.Message
}

func (r *bitwardenCredentialResolver) Resolve(
	ctx context.Context,
	entry credential.Entry,
) (string, error) {
	output, err := r.runAAC(ctx, entry)
	if err != nil {
		return "", err
	}

	var result bitwardenConnectResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return "", &bitwardenResolutionError{
			Entry:   entry,
			Message: fmt.Sprintf("bitwarden returned invalid JSON: %v", err),
		}
	}
	if !result.Success {
		return "", &bitwardenResolutionError{
			Entry:   entry,
			Message: "bitwarden did not return a successful credential response",
		}
	}

	value, err := selectBitwardenField(entry, result)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", &bitwardenResolutionError{
			Entry:   entry,
			Message: fmt.Sprintf("bitwarden field %q was empty", bitwardenField(entry)),
		}
	}

	return value, nil
}

func (r *bitwardenCredentialResolver) runAAC(
	ctx context.Context,
	entry credential.Entry,
) ([]byte, error) {
	aacBin := os.Getenv("KONTEXT_BITWARDEN_AAC_BIN")
	if strings.TrimSpace(aacBin) == "" {
		aacBin = defaultAACBin
	}

	args := []string{"connect", "--output", "json"}
	if token := strings.TrimSpace(os.Getenv("KONTEXT_BITWARDEN_TOKEN")); token != "" {
		args = append(args, "--token", token)
	}
	if provider := strings.TrimSpace(os.Getenv("KONTEXT_BITWARDEN_PROVIDER")); provider != "" {
		args = append(args, "--provider", provider)
	}

	switch {
	case strings.HasPrefix(entry.Provider, "id:"):
		args = append(args, "--id", strings.TrimPrefix(entry.Provider, "id:"))
	case strings.HasPrefix(entry.Provider, "domain:"):
		args = append(args, "--domain", strings.TrimPrefix(entry.Provider, "domain:"))
	default:
		args = append(args, "--domain", entry.Provider)
	}

	cmd := exec.CommandContext(ctx, aacBin, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return output, nil
	}

	var missing *exec.Error
	if errors.As(err, &missing) && errors.Is(missing.Err, exec.ErrNotFound) {
		return nil, &bitwardenResolutionError{
			Entry:   entry,
			Message: fmt.Sprintf("bitwarden cli %q was not found in PATH; install Agent Access or set KONTEXT_BITWARDEN_AAC_BIN", aacBin),
		}
	}

	msg := strings.TrimSpace(string(output))
	if msg == "" {
		msg = err.Error()
	}
	return nil, &bitwardenResolutionError{
		Entry:   entry,
		Message: fmt.Sprintf("bitwarden credential fetch failed: %s", msg),
	}
}

func (r *bitwardenCredentialResolver) UnresolvedConnectableEntries(
	_ map[string]credential.Entry,
	_ map[string]error,
) []credential.Entry {
	return nil
}

func (r *bitwardenCredentialResolver) ConnectAndRetry(
	_ context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	return nil, failureMap(entries, errors.New("bitwarden reconnect flow is not implemented in kontext-cli"))
}

func (r *bitwardenCredentialResolver) PrintLaunchWarnings(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) {
	for envVar, err := range failures {
		entry, ok := entryByEnvVar[envVar]
		if !ok || entry.Scheme != bitwardenScheme {
			continue
		}
		fmt.Fprintf(os.Stderr, "⚠ %s could not be resolved from Bitwarden (%v)\n", entry.EnvVar, err)
	}
}

func bitwardenField(entry credential.Entry) string {
	if entry.Resource == "" {
		return "password"
	}
	return entry.Resource
}

func selectBitwardenField(
	entry credential.Entry,
	result bitwardenConnectResponse,
) (string, error) {
	switch bitwardenField(entry) {
	case "username":
		return result.Credential.Username, nil
	case "password":
		return result.Credential.Password, nil
	case "totp":
		return result.Credential.TOTP, nil
	case "uri":
		if result.Credential.URI != "" {
			return result.Credential.URI, nil
		}
		return result.Domain, nil
	case "notes":
		return result.Credential.Notes, nil
	case "domain":
		return result.Domain, nil
	case "credential_id":
		if result.CredentialID != "" {
			return result.CredentialID, nil
		}
		return result.Credential.ID, nil
	default:
		return "", &bitwardenResolutionError{
			Entry:   entry,
			Message: fmt.Sprintf("unsupported bitwarden field %q", entry.Resource),
		}
	}
}
