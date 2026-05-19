package managedconfig

import (
	"errors"
	"regexp"
	"strings"
)

type CredentialRef struct {
	Scheme string
	Name   string
}

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func ParseCredentialRef(raw string) (CredentialRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return CredentialRef{}, errors.New("install token reference is required")
	}
	scheme, value, ok := strings.Cut(raw, ":")
	if !ok {
		return CredentialRef{}, errors.New("install token reference must use keychain: or env:")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return CredentialRef{}, errors.New("install token reference value is required")
	}
	switch scheme {
	case "keychain":
		if strings.ContainsAny(value, "\n\r\t") {
			return CredentialRef{}, errors.New("keychain service name must be a single value")
		}
		return CredentialRef{Scheme: scheme, Name: value}, nil
	case "env":
		if !envNamePattern.MatchString(value) {
			return CredentialRef{}, errors.New("env token reference must be an environment variable name")
		}
		return CredentialRef{Scheme: scheme, Name: value}, nil
	default:
		return CredentialRef{}, errors.New("install token reference must use keychain: or env:")
	}
}

func RedactCredentialRef(raw string) string {
	ref, err := ParseCredentialRef(raw)
	if err != nil {
		return ""
	}
	return ref.Scheme + ":" + ref.Name
}
