package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cli/browser"
	"golang.org/x/oauth2"
)

const (
	// Well-known public client for the Kontext CLI. No secret.
	DefaultClientID = "app_a4fb6d20-e937-450f-aa19-db585405aa92"

	// Default API base URL.
	DefaultIssuerURL = "https://api.kontext.security"
)

var defaultLoginScopes = []string{
	"openid",
	"email",
	"profile",
	"offline_access",
}

var identityLoginScopes = []string{
	"openid",
	"email",
	"profile",
}

// LoginResult is the output of a successful login flow.
type LoginResult struct {
	Session *Session
}

// OAuthMetadata is the response from /.well-known/oauth-authorization-server.
type OAuthMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// DiscoverEndpoints fetches OAuth authorization server metadata.
func DiscoverEndpoints(ctx context.Context, baseURL string) (*OAuthMetadata, error) {
	url := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery failed: %s", resp.Status)
	}

	var meta OAuthMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode discovery: %w", err)
	}

	return &meta, nil
}

// Login performs the browser-based OAuth PKCE login flow.
// When scopes are omitted, the default CLI login scopes are used.
func Login(ctx context.Context, issuerURL, clientID string, scopes ...string) (*LoginResult, error) {
	// 1. Discover endpoints
	meta, err := DiscoverEndpoints(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oauth discovery failed for %s: %w", issuerURL, err)
	}

	// 2. Start localhost callback server
	callbackCh := make(chan callbackResult, 1)
	// Use port 0 — Ory Hydra allows any port on localhost for native apps
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
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  meta.AuthorizationEndpoint,
			TokenURL: meta.TokenEndpoint,
		},
		RedirectURL: redirectURI,
		Scopes:      resolveLoginScopes(scopes),
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

	// 9. Extract user info from the ID token.
	session := &Session{
		IssuerURL:    issuerURL,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}

	// Try to decode ID token for user claims
	if rawIDToken, ok := token.Extra("id_token").(string); ok {
		if err := applyIDTokenClaims(session, rawIDToken); err != nil {
			return nil, err
		}
	}
	if session.Subject == "" {
		return nil, fmt.Errorf("id token missing subject claim")
	}

	applyTokenExtraEmailFallback(session, token)

	return &LoginResult{Session: session}, nil
}

func applyIDTokenClaims(session *Session, rawIDToken string) error {
	session.IDToken = rawIDToken
	claims, err := decodeJWTClaims(rawIDToken)
	if err != nil {
		return err
	}

	if claims.Subject == "" {
		return fmt.Errorf("id token missing subject claim")
	}
	session.Subject = claims.Subject
	session.User.Name = claims.Name
	session.User.Email = claims.Email
	return nil
}

func resolveLoginScopes(scopes []string) []string {
	baseScopes := defaultLoginScopes
	if len(scopes) > 0 {
		baseScopes = identityLoginScopes
	}

	resolved := append([]string(nil), baseScopes...)
	for _, scope := range scopes {
		if !hasScope(resolved, scope) {
			resolved = append(resolved, scope)
		}
	}
	return resolved
}

func hasScope(scopes []string, scope string) bool {
	for _, existing := range scopes {
		if existing == scope {
			return true
		}
	}
	return false
}

func applyTokenExtraEmailFallback(session *Session, token *oauth2.Token) {
	if session.User.Email != "" {
		return
	}
	if email, _ := token.Extra("email").(string); email != "" {
		session.User.Email = email
	}
}

// RefreshSession attempts to refresh an expired session using the refresh token.
func RefreshSession(ctx context.Context, session *Session) (*Session, error) {
	if session.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	meta, err := DiscoverEndpoints(ctx, session.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oauth discovery: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID: DefaultClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  meta.AuthorizationEndpoint,
			TokenURL: meta.TokenEndpoint,
		},
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
	if _, err := session.IdentityKey(); err != nil {
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

type jwtClaims struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
}

// decodeJWTClaims decodes the payload of a JWT without verification.
// Used only for extracting user display info — not for security decisions.
func decodeJWTClaims(rawToken string) (jwtClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return jwtClaims{}, fmt.Errorf("invalid JWT format")
	}

	// Add padding if needed
	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return jwtClaims{}, err
	}

	var claims jwtClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return jwtClaims{}, err
	}

	return claims, nil
}

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
