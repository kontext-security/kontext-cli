package bitwarden

import "testing"

func TestValidateReusablePSKTokenAcceptsExpectedFormat(t *testing.T) {
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := ValidateReusablePSKToken(token); err != nil {
		t.Fatalf("ValidateReusablePSKToken() error = %v", err)
	}
}

func TestValidateReusablePSKTokenRejectsInvalidFormat(t *testing.T) {
	t.Parallel()

	if err := ValidateReusablePSKToken("ABC-DEF-123"); err == nil {
		t.Fatal("ValidateReusablePSKToken() error = nil, want non-nil")
	}
}
