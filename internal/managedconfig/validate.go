package managedconfig

import (
	"net/url"
	"regexp"
	"strings"
)

var jwtLikePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func Validate(cfg Config) []ValidationError {
	var errs []ValidationError
	if cfg.Version != SchemaVersion {
		errs = append(errs, ValidationError{Code: "unsupported_version", Field: "version", Message: `version must be "managed-install-v1"`})
	}
	if strings.TrimSpace(cfg.OrganizationID) == "" {
		errs = append(errs, ValidationError{Code: "required", Field: "organization_id", Message: "organization_id is required"})
	}
	if strings.TrimSpace(cfg.CloudURL) == "" {
		errs = append(errs, ValidationError{Code: "required", Field: "cloud_url", Message: "cloud_url is required"})
	} else if cloudErr := validateCloudURL(cfg.CloudURL); cloudErr != nil {
		errs = append(errs, *cloudErr)
	}
	if cfg.Mode != DefaultMode {
		errs = append(errs, ValidationError{Code: "unsupported_mode", Field: "mode", Message: "only observe is supported in managed-install-v1"})
	}
	if cfg.Agent != DefaultAgent {
		errs = append(errs, ValidationError{Code: "unsupported_agent", Field: "agent", Message: "only claude is supported in managed-install-v1"})
	}
	if cfg.Device.Label != nil {
		label := strings.TrimSpace(*cfg.Device.Label)
		if label == "" {
			errs = append(errs, ValidationError{Code: "invalid_device_label", Field: "device.label", Message: "device label must be non-empty when provided"})
		} else if len(label) > 128 {
			errs = append(errs, ValidationError{Code: "invalid_device_label", Field: "device.label", Message: "device label must be 128 characters or fewer"})
		}
	}
	tokenRef := strings.TrimSpace(cfg.Credentials.InstallTokenRef)
	if tokenRef == "" {
		errs = append(errs, ValidationError{Code: "required", Field: "credentials.install_token_ref", Message: "install token reference is required"})
	} else if looksLikeRawToken(tokenRef) {
		errs = append(errs, ValidationError{Code: "inline_secret_rejected", Field: "credentials.install_token_ref", Message: "install tokens must be referenced, not stored inline"})
	} else if _, err := ParseCredentialRef(tokenRef); err != nil {
		errs = append(errs, ValidationError{Code: "invalid_credential_ref", Field: "credentials.install_token_ref", Message: err.Error()})
	}
	return errs
}

func validateCloudURL(raw string) *ValidationError {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return &ValidationError{Code: "invalid_cloud_url", Field: "cloud_url", Message: "cloud_url must be an absolute https URL"}
	}
	if parsed.Scheme != "https" {
		return &ValidationError{Code: "invalid_cloud_url", Field: "cloud_url", Message: "cloud_url must use https"}
	}
	if parsed.User != nil {
		return &ValidationError{Code: "invalid_cloud_url", Field: "cloud_url", Message: "cloud_url must not contain username or password"}
	}
	if parsed.RawQuery != "" {
		return &ValidationError{Code: "invalid_cloud_url", Field: "cloud_url", Message: "cloud_url must not contain a query string"}
	}
	if parsed.Fragment != "" {
		return &ValidationError{Code: "invalid_cloud_url", Field: "cloud_url", Message: "cloud_url must not contain a fragment"}
	}
	return nil
}

func looksLikeRawToken(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "token:") || strings.HasPrefix(lower, "bearer:") || strings.HasPrefix(lower, "sk_") {
		return true
	}
	if jwtLikePattern.MatchString(raw) {
		return true
	}
	if !strings.Contains(raw, ":") && len(raw) >= 32 {
		return true
	}
	return false
}
