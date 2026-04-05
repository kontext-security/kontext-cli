package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cli/browser"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// Well-known public client for the Kontext CLI. No secret.
	// This must be pre-registered in Hydra with:
	//   grant_types: ["authorization_code", "refresh_token"]
	//   token_endpoint_auth_method: "none"
	//   redirect_uris: ["http://127.0.0.1/callback", "http://localhost/callback"]
	DefaultClientID = "kontext-cli"

	// Default issuer URL. Override with --issuer-url flag or KONTEXT_ISSUER_URL env.
	DefaultIssuerURL = "https://api.kontext.security"
)

// LoginResult is the output of a successful OIDC login flow.
type LoginResult struct {
	Session *Session
}

// Login performs the browser-based OIDC PKCE login flow.
func Login(ctx context.Context, issuerURL, clientID string) (*LoginResult, error) {
	// 1. OIDC discovery
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed for %s: %w", issuerURL, err)
	}

	// 2. Start localhost callback server
	callbackCh := make(chan callbackResult, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	srv := &http.Server{Handler: callbackHandler(callbackCh)}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// 3. Generate PKCE verifier + challenge
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}

	// 4. Build OAuth2 config
	oauthConfig := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile", "offline_access"},
	}

	// 5. Generate state parameter
	state, err := randomString(16)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	// 6. Open browser
	authURL := oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	fmt.Fprintln(os.Stderr, "Opening browser for login...")
	fmt.Fprintf(os.Stderr, "If the browser doesn't open, visit:\n  %s\n\n", authURL)
	_ = browser.OpenURL(authURL)

	// 7. Wait for callback
	var result callbackResult
	select {
	case result = <-callbackCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if result.err != nil {
		return nil, result.err
	}

	if result.state != state {
		return nil, fmt.Errorf("oauth state mismatch")
	}

	// 8. Exchange code for tokens
	token, err := oauthConfig.Exchange(ctx, result.code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	// 9. Verify and decode ID token
	verifierConfig := &oidc.Config{ClientID: clientID}
	idTokenVerifier := provider.Verifier(verifierConfig)

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	var claims struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}

	// 10. Build session
	session := &Session{
		IssuerURL:    issuerURL,
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}
	session.User.Name = claims.Name
	session.User.Email = claims.Email

	return &LoginResult{Session: session}, nil
}

// RefreshSession attempts to refresh an expired session using the refresh token.
func RefreshSession(ctx context.Context, session *Session) (*Session, error) {
	if session.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	provider, err := oidc.NewProvider(ctx, session.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID: DefaultClientID,
		Endpoint: provider.Endpoint(),
	}

	tokenSource := oauthConfig.TokenSource(ctx, &oauth2.Token{
		RefreshToken: session.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour), // force refresh
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	session.AccessToken = newToken.AccessToken
	session.ExpiresAt = newToken.Expiry
	if newToken.RefreshToken != "" {
		session.RefreshToken = newToken.RefreshToken
	}

	return session, nil
}

// Preflight loads the session and refreshes if needed. Returns a ready-to-use session.
func Preflight(ctx context.Context) (*Session, error) {
	session, err := LoadSession()
	if err != nil {
		return nil, err
	}

	if !session.IsExpired() {
		return session, nil
	}

	session, err = RefreshSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("session expired and refresh failed (run `kontext login`): %w", err)
	}

	if err := SaveSession(session); err != nil {
		return nil, fmt.Errorf("save refreshed session: %w", err)
	}

	return session, nil
}

// --- helpers ---

type callbackResult struct {
	code  string
	state string
	err   error
}

func callbackHandler(ch chan<- callbackResult) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}

		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<h1>Login failed</h1><p>%s: %s</p><p>You can close this tab.</p>", errMsg, desc)
			ch <- callbackResult{err: fmt.Errorf("oauth error: %s: %s", errMsg, desc)}
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<h1>Missing code</h1><p>Please try again.</p>")
			ch <- callbackResult{err: fmt.Errorf("no authorization code received")}
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<h1>Login successful!</h1><p>You can close this tab and return to the terminal.</p>")
		ch <- callbackResult{code: code, state: state}
	})
}

func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

