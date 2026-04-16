package auth

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
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

func TestResolveLoginScopesCustom(t *testing.T) {
	t.Parallel()

	input := []string{"gateway:access"}
	got := resolveLoginScopes(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("resolveLoginScopes(%#v) = %#v", input, got)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(input)) {
		t.Fatal("resolveLoginScopes(custom) returned a shared slice")
	}
}

func TestDecodeJWTClaims(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(map[string]string{
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
	if got.Name != "Ada Lovelace" || got.Email != "ada@example.com" {
		t.Fatalf("decodeJWTClaims() = %#v, want name and email extracted", got)
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
