package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	keyringService = "kontext-cli"
	keyringUser    = "default"
	refreshBuffer  = 60 * time.Second
)

// Session holds the authenticated user's OIDC identity and tokens.
type Session struct {
	User         UserInfo  `json:"user"`
	IssuerURL    string    `json:"issuer_url"`
	Subject      string    `json:"subject"`
	AccessToken  string    `json:"access_token"`
	IDToken      string    `json:"id_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// UserInfo holds the user identity extracted from the ID token.
type UserInfo struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// IsExpired returns true if the access token has expired or will expire within the buffer.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt.Add(-refreshBuffer))
}

// IdentityKey returns the stable identity used for backend session attribution.
func (s *Session) IdentityKey() (string, error) {
	issuer := strings.TrimRight(strings.TrimSpace(s.IssuerURL), "/")
	subject := strings.TrimSpace(s.Subject)
	if issuer == "" || subject == "" {
		return "", fmt.Errorf("stored session is missing identity information (run `kontext login`)")
	}
	return issuer + "#" + subject, nil
}

// DisplayIdentity returns the human-readable identity for terminal output.
func (s *Session) DisplayIdentity() string {
	if s.User.Email != "" {
		return s.User.Email
	}
	return s.User.Name
}

// LoadSession reads the stored session from the system keyring.
func LoadSession() (*Session, error) {
	data, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		return nil, fmt.Errorf("no stored session (run `kontext login`): %w", err)
	}

	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("corrupt session in keyring: %w", err)
	}

	return &session, nil
}

// SaveSession stores the session in the system keyring.
func SaveSession(session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	return keyring.Set(keyringService, keyringUser, string(data))
}

// ClearSession removes the stored session from the system keyring.
func ClearSession() error {
	return keyring.Delete(keyringService, keyringUser)
}
