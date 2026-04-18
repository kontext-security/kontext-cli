package auth

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestResolveLoginScopesDefaults(t *testing.T) {
	t.Parallel()

	got := resolveLoginScopes(nil)
	want := []string{
		"openid",
		"email",
		"profile",
		"offline_access",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveLoginScopes(nil) = %#v, want %#v", got, want)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(nil)) {
		t.Fatal("resolveLoginScopes(nil) returned a shared slice")
	}
}

func TestResolveLoginScopesAddsCustomScopes(t *testing.T) {
	t.Parallel()

	input := []string{"gateway:access"}
	got := resolveLoginScopes(input)
	want := []string{
		"openid",
		"email",
		"profile",
		"gateway:access",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveLoginScopes(%#v) = %#v, want %#v", input, got, want)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(input)) {
		t.Fatal("resolveLoginScopes(custom) returned a shared slice")
	}
}

func TestResolveLoginScopesDeduplicatesDefaultScopes(t *testing.T) {
	t.Parallel()

	input := []string{"openid", "gateway:access"}
	got := resolveLoginScopes(input)
	want := []string{
		"openid",
		"email",
		"profile",
		"gateway:access",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveLoginScopes(%#v) = %#v, want %#v", input, got, want)
	}
}

func TestDecodeJWTClaims(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(map[string]string{
		"sub":   "user-123",
		"name":  "Ada Lovelace",
		"email": "ada@example.com",
		"role":  "admin",
	})
	if err != nil {
		t.Fatalf("json.Marshal() = %v", err)
	}

	raw := "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	got, err := decodeJWTClaims(raw)
	if err != nil {
		t.Fatalf("decodeJWTClaims() error = %v", err)
	}
	if got.Subject != "user-123" || got.Name != "Ada Lovelace" || got.Email != "ada@example.com" {
		t.Fatalf("decodeJWTClaims() = %#v, want subject, name, and email extracted", got)
	}
}

func TestApplyTokenExtraEmailFallback(t *testing.T) {
	t.Parallel()

	session := &Session{}
	token := (&oauth2.Token{}).WithExtra(map[string]any{"email": "ada@example.com"})

	applyTokenExtraEmailFallback(session, token)
	if session.User.Email != "ada@example.com" {
		t.Fatalf("session.User.Email = %q, want token extra email", session.User.Email)
	}
}

func TestApplyTokenExtraEmailFallbackKeepsIDTokenEmail(t *testing.T) {
	t.Parallel()

	session := &Session{User: UserInfo{Email: "id-token@example.com"}}
	token := (&oauth2.Token{}).WithExtra(map[string]any{"email": "extra@example.com"})

	applyTokenExtraEmailFallback(session, token)
	if session.User.Email != "id-token@example.com" {
		t.Fatalf("session.User.Email = %q, want ID token email", session.User.Email)
	}
}

func TestApplyIDTokenClaimsRequiresSubject(t *testing.T) {
	t.Parallel()

	session := &Session{}
	err := applyIDTokenClaims(session, unsignedJWT(map[string]any{
		"email": "dev@example.com",
	}))
	if err == nil {
		t.Fatal("applyIDTokenClaims() error = nil, want missing subject error")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("applyIDTokenClaims() error = %q, want subject message", err)
	}
}

func TestApplyIDTokenClaimsStoresSubjectAndDisplayClaims(t *testing.T) {
	t.Parallel()

	session := &Session{}
	err := applyIDTokenClaims(session, unsignedJWT(map[string]any{
		"sub":   "user-123",
		"name":  "Dev User",
		"email": "dev@example.com",
	}))
	if err != nil {
		t.Fatalf("applyIDTokenClaims() error = %v", err)
	}
	if session.Subject != "user-123" {
		t.Fatalf("session.Subject = %q, want user-123", session.Subject)
	}
	if got := session.DisplayIdentity(); got != "dev@example.com" {
		t.Fatalf("DisplayIdentity() = %q, want email", got)
	}
}

func TestSessionIdentityKeyUsesIssuerAndSubject(t *testing.T) {
	t.Parallel()

	session := &Session{IssuerURL: "https://api.kontext.security/"}
	session.Subject = "user-123"

	got, err := session.IdentityKey()
	if err != nil {
		t.Fatalf("IdentityKey() error = %v", err)
	}
	want := "https://api.kontext.security#user-123"
	if got != want {
		t.Fatalf("IdentityKey() = %q, want %q", got, want)
	}
}

func TestSessionIdentityKeyRejectsLegacySession(t *testing.T) {
	t.Parallel()

	session := &Session{IssuerURL: "https://api.kontext.security"}
	_, err := session.IdentityKey()
	if err == nil {
		t.Fatal("IdentityKey() error = nil, want missing identity error")
	}
	if !strings.Contains(err.Error(), "kontext login") {
		t.Fatalf("IdentityKey() error = %q, want login hint", err)
	}
}

func unsignedJWT(claims map[string]any) string {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	return encodeJWTPart(header) + "." + encodeJWTPart(claims) + "."
}

func encodeJWTPart(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
