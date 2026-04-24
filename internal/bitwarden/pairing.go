package bitwarden

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	keyringService = "kontext-cli"
	pairingUser    = "bitwarden-reusable-psk"
)

var reusablePSKTokenPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}_[0-9a-fA-F]{64}$`)

func ValidateReusablePSKToken(token string) error {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return fmt.Errorf("bitwarden PSK token is required")
	}
	if !reusablePSKTokenPattern.MatchString(trimmed) {
		return fmt.Errorf("bitwarden PSK token must match <64 hex>_<64 hex>")
	}
	return nil
}

func SaveReusablePSKToken(token string) error {
	if err := ValidateReusablePSKToken(token); err != nil {
		return err
	}
	return keyring.Set(keyringService, pairingUser, strings.TrimSpace(token))
}

func LoadReusablePSKToken() (string, error) {
	token, err := keyring.Get(keyringService, pairingUser)
	if err != nil {
		return "", err
	}
	if err := ValidateReusablePSKToken(token); err != nil {
		return "", fmt.Errorf("stored Bitwarden PSK token is invalid: %w", err)
	}
	return strings.TrimSpace(token), nil
}

func ClearReusablePSKToken() error {
	return keyring.Delete(keyringService, pairingUser)
}
