package diagnostic

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnabledFromEnvRequiresOne(t *testing.T) {
	t.Setenv("KONTEXT_DEBUG", "1")
	if !EnabledFromEnv() {
		t.Fatal("EnabledFromEnv() = false, want true")
	}

	t.Setenv("KONTEXT_DEBUG", "true")
	if EnabledFromEnv() {
		t.Fatal("EnabledFromEnv() = true, want false")
	}
}

func TestLoggerWritesRedactedDiagnosticsOnlyWhenEnabled(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, false)
	logger.Printf("Authorization: Bearer secret-token")
	if output.String() != "" {
		t.Fatalf("disabled logger output = %q, want empty", output.String())
	}

	logger = New(&output, true)
	logger.Printf("Authorization: Bearer secret-token code=secret-code")
	got := output.String()
	if strings.Contains(got, "secret-token") || strings.Contains(got, "secret-code") {
		t.Fatalf("diagnostic output leaked secret: %q", got)
	}
	if !strings.Contains(got, "Bearer [REDACTED]") || !strings.Contains(got, "code=[REDACTED]") {
		t.Fatalf("diagnostic output = %q, want redacted markers", got)
	}
}

func TestLoggerRedactsJSONSecrets(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, true)

	logger.Printf(`{"access_token":"secret-token","code":"secret-code","message":"keep"}`)
	got := output.String()
	if strings.Contains(got, "secret-token") || strings.Contains(got, "secret-code") {
		t.Fatalf("diagnostic output leaked JSON secret: %q", got)
	}
	if !strings.Contains(got, `"access_token":"[REDACTED]"`) || !strings.Contains(got, `"code":"[REDACTED]"`) {
		t.Fatalf("diagnostic output = %q, want JSON redaction markers", got)
	}
	if !strings.Contains(got, `"message":"keep"`) {
		t.Fatalf("diagnostic output = %q, want non-secret fields preserved", got)
	}
}
