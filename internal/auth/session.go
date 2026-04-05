package auth

import (
	"encoding/json"
	"fmt"
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
	User struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"user"`
	IssuerURL    string    `json:"issuer_url"`
	AccessToken  string    `json:"access_token"`
	IDToken      string    `json:"id_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired returns true if the access token has expired or will expire within the buffer.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt.Add(-refreshBuffer))
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
