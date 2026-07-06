package payloadcapture

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type captureVector struct {
	Name        string          `json:"name"`
	Input       json.RawMessage `json:"input"`
	CaptureMode Mode            `json:"captureMode"`
	Expected    map[string]any  `json:"expected"`
}

func decodeInputMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	value, ok := decodeUseNumber(t, raw).(map[string]any)
	if !ok {
		t.Fatalf("fixture input is not an object: %s", raw)
	}
	return value
}

func marshalRecord(t *testing.T, payload *Payload) map[string]any {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("unmarshal payload record: %v", err)
	}
	return record
}

// TestCaptureAgainstSharedVectors exercises the redaction-independent parts
// of the shared capture vectors. Fields derived from redaction output
// (stored fingerprints, exact redacted bytes) are asserted for
// self-consistency, not byte-equality: engines share coverage guarantees,
// not identical output.
func TestCaptureAgainstSharedVectors(t *testing.T) {
	t.Parallel()

	var vectors []captureVector
	loadTestdata(t, "captured-payload-vectors.json", &vectors)

	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			input := decodeInputMap(t, vector.Input)

			if vector.Expected == nil {
				if payload := Capture(input, vector.CaptureMode); payload != nil {
					t.Fatalf("expected no record in %s mode, got %v", vector.CaptureMode, payload)
				}
				return
			}

			expectedMode, _ := vector.Expected["mode"].(string)
			switch expectedMode {
			case string(ModeOmitted):
				payload := Capture(input, vector.CaptureMode)
				if payload == nil {
					t.Fatal("expected an omitted record")
				}
				record := marshalRecord(t, payload)
				if record["mode"] != string(ModeOmitted) {
					t.Fatalf("mode = %v", record["mode"])
				}
				if got, want := record["sourceByteLength"], vector.Expected["sourceByteLength"]; got != want {
					t.Fatalf("sourceByteLength = %v, want %v", got, want)
				}
				if _, hasHash := record["sourceSha256"]; hasHash {
					t.Fatal("omitted records must not carry a fingerprint")
				}
			case string(ModeFull):
				payload := Capture(input, vector.CaptureMode)
				if payload == nil {
					t.Fatal("expected a full record")
				}
				record := marshalRecord(t, payload)
				if record["mode"] != string(ModeFull) {
					t.Fatalf("mode = %v", record["mode"])
				}
				// Source commitment is redaction-independent and must match
				// the shared vector byte-for-byte.
				if got, want := record["sourceSha256"], vector.Expected["sourceSha256"]; got != want {
					t.Fatalf("sourceSha256 = %v, want %v", got, want)
				}
				if got, want := record["sourceByteLength"], vector.Expected["sourceByteLength"]; got != want {
					t.Fatalf("sourceByteLength = %v, want %v", got, want)
				}
				if got, want := record["redactorVersion"], RedactorVersion; got != want {
					t.Fatalf("redactorVersion = %v, want %v", got, want)
				}
				assertStoredConsistency(t, payload)
			default:
				// Truncation and failure vectors document the record shape;
				// their inputs are placeholders that cannot drive this
				// engine into those states. Dedicated tests below cover the
				// real triggers. Still pin the mode-independent fields so
				// fixture drift cannot hide here.
				if version, ok := vector.Expected["redactorVersion"]; ok && version != RedactorVersion {
					t.Fatalf("fixture redactorVersion = %v, engine emits %v", version, RedactorVersion)
				}
			}
		})
	}
}

func assertStoredConsistency(t *testing.T, payload *Payload) {
	t.Helper()
	switch payload.Mode {
	case string(ModeFull):
		canonical, err := CanonicalJSON(payload.Value)
		if err != nil {
			t.Fatalf("canonicalize stored value: %v", err)
		}
		if payload.StoredSha256 != sha256Hex(canonical) {
			t.Fatal("storedSha256 does not match stored value")
		}
		if payload.StoredByteLength != len(canonical) {
			t.Fatal("storedByteLength does not match stored value")
		}
	case modeFullTruncated:
		if payload.StoredSha256 != sha256Hex([]byte(payload.Preview)) {
			t.Fatal("storedSha256 does not match preview")
		}
		if payload.StoredByteLength != len(payload.Preview) {
			t.Fatal("storedByteLength does not match preview")
		}
	}
}

func TestCaptureFullRedactsSecrets(t *testing.T) {
	t.Parallel()

	payload := Capture(map[string]any{
		"command": "curl -H \"Authorization: Bearer raw-token-value\" https://example.test",
		"api_key": "raw-token-value",
	}, ModeFull)
	if payload == nil || payload.Mode != string(ModeFull) {
		t.Fatalf("expected full record, got %v", payload)
	}
	if !payload.Redacted {
		t.Fatal("expected redacted flag")
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "raw-token-value") {
		t.Fatal("secret survived capture")
	}
}

func TestCaptureTruncatesOversizedPayloads(t *testing.T) {
	t.Parallel()

	payload := Capture(map[string]any{
		"content": strings.Repeat("a", 200_000),
		"emoji":   strings.Repeat("😀", 5_000),
	}, ModeFull)
	if payload == nil || payload.Mode != modeFullTruncated {
		t.Fatalf("expected truncated record, got %v", payload)
	}

	size, err := serializedSize(payload)
	if err != nil {
		t.Fatalf("serializedSize: %v", err)
	}
	if size > MaxPayloadBytes {
		t.Fatalf("serialized record is %d bytes, cap is %d", size, MaxPayloadBytes)
	}
	if !strings.Contains(payload.Preview, "[truncated ") ||
		!strings.HasSuffix(payload.Preview, " bytes total]") {
		t.Fatalf("marker missing from preview tail: %q", payload.Preview[len(payload.Preview)-64:])
	}
	if !utf8.ValidString(payload.Preview) {
		t.Fatal("preview is not valid UTF-8")
	}
	assertStoredConsistency(t, payload)
}

func TestCaptureAtCapVectorMeasuresExactly(t *testing.T) {
	t.Parallel()

	var fixture struct {
		Payload struct {
			Preview          string `json:"preview"`
			Redacted         bool   `json:"redacted"`
			SourceSha256     string `json:"sourceSha256"`
			SourceByteLength int    `json:"sourceByteLength"`
			StoredSha256     string `json:"storedSha256"`
			StoredByteLength int    `json:"storedByteLength"`
		} `json:"payload"`
	}
	loadTestdata(t, "at-cap-envelope-vector.json", &fixture)

	payload := &Payload{
		Mode:             modeFullTruncated,
		Preview:          fixture.Payload.Preview,
		Redacted:         fixture.Payload.Redacted,
		SourceSha256:     fixture.Payload.SourceSha256,
		SourceByteLength: fixture.Payload.SourceByteLength,
		StoredSha256:     fixture.Payload.StoredSha256,
		StoredByteLength: fixture.Payload.StoredByteLength,
	}

	size, err := serializedSize(payload)
	if err != nil {
		t.Fatalf("serializedSize: %v", err)
	}
	if size != MaxPayloadBytes {
		t.Fatalf("at-cap vector measures %d bytes, want exactly %d", size, MaxPayloadBytes)
	}
	assertStoredConsistency(t, payload)
}

func TestCaptureFailurePathsNeverLeakContent(t *testing.T) {
	t.Parallel()

	secret := "unserializable-companion-secret"

	serializationFailure := Capture(map[string]any{
		"fn":     func() {},
		"secret": secret,
	}, ModeFull)
	if serializationFailure == nil || serializationFailure.Reason != ReasonSerializationError {
		t.Fatalf("expected serialization_error, got %v", serializationFailure)
	}

	oversized := Capture(map[string]any{
		"content": strings.Repeat("b", InputHardCapBytes+1),
	}, ModeFull)
	if oversized == nil || oversized.Reason != ReasonSizePrecheckExceeded {
		t.Fatalf("expected size_precheck_exceeded, got %v", oversized)
	}

	for _, payload := range []*Payload{serializationFailure, oversized} {
		record := marshalRecord(t, payload)
		if record["mode"] != modeFailed {
			t.Fatalf("mode = %v", record["mode"])
		}
		raw, _ := json.Marshal(payload)
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("bbbb")) {
			t.Fatalf("failure record leaked content: %s", raw)
		}
	}
}

func TestCaptureSkipsSummaryUnknownAndEmpty(t *testing.T) {
	t.Parallel()

	input := map[string]any{"command": "git status"}
	if Capture(input, ModeSummary) != nil {
		t.Fatal("summary mode must produce no record")
	}
	if Capture(input, Mode("enforce-everything")) != nil {
		t.Fatal("unknown mode must produce no record")
	}
	if Capture(nil, ModeFull) != nil {
		t.Fatal("empty input must produce no record")
	}
}

// Regression test: the truncation search previously advanced its lower bound
// from the boundary-snapped probe, which stops making progress when the
// probe window sits inside a long run of multi-byte runes — an infinite loop
// on the hook path for emoji-heavy payloads.
func TestCaptureTruncatesMultiByteHeavyPayloadsWithoutHanging(t *testing.T) {
	t.Parallel()

	done := make(chan *Payload, 1)
	go func() {
		done <- Capture(map[string]any{
			"content": strings.Repeat("😀", 80_000),
		}, ModeFull)
	}()

	select {
	case payload := <-done:
		if payload == nil || payload.Mode != modeFullTruncated {
			t.Fatalf("expected truncated record, got %v", payload)
		}
		size, err := serializedSize(payload)
		if err != nil {
			t.Fatalf("serializedSize: %v", err)
		}
		if size > MaxPayloadBytes {
			t.Fatalf("serialized record is %d bytes, cap is %d", size, MaxPayloadBytes)
		}
		if !utf8.ValidString(payload.Preview) {
			t.Fatal("preview is not valid UTF-8")
		}
		assertStoredConsistency(t, payload)
	case <-time.After(30 * time.Second):
		t.Fatal("truncation did not terminate")
	}
}

func TestSerializedSizeDoesNotEscapeHTMLCharacters(t *testing.T) {
	t.Parallel()

	base := Capture(map[string]any{"content": strings.Repeat("a", 100)}, ModeFull)
	angled := Capture(map[string]any{"content": strings.Repeat("<", 100)}, ModeFull)
	baseSize, err := serializedSize(base)
	if err != nil {
		t.Fatalf("serializedSize: %v", err)
	}
	angledSize, err := serializedSize(angled)
	if err != nil {
		t.Fatalf("serializedSize: %v", err)
	}
	// '<' must count as one byte like any other ASCII character; HTML
	// escaping would count it as six and force needless truncation.
	if baseSize != angledSize {
		t.Fatalf("size diverged: %d (plain) vs %d (angle brackets)", baseSize, angledSize)
	}
}

func TestUtf8Boundary(t *testing.T) {
	t.Parallel()

	data := []byte("a😀b") // 1 + 4 + 1 bytes
	cases := []struct{ cut, want int }{
		{0, 0},
		{1, 1},
		{2, 1}, // inside the emoji
		{3, 1},
		{4, 1},
		{5, 5},
		{6, 6},
		{99, 6}, // past the end clamps
	}
	for _, tc := range cases {
		if got := utf8Boundary(data, tc.cut); got != tc.want {
			t.Errorf("utf8Boundary(%d) = %d, want %d", tc.cut, got, tc.want)
		}
	}
	if got := utf8Boundary(nil, 3); got != 0 {
		t.Errorf("utf8Boundary(nil, 3) = %d, want 0", got)
	}
}

func TestCaptureIsDeterministic(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"command": "curl https://example.test",
		"z":       "last",
		"a":       "first",
		"nested":  map[string]any{"beta": 2, "alpha": 1},
		"api_key": "raw-secret",
	}

	first, err := json.Marshal(Capture(input, ModeFull))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for range 1000 {
		next, err := json.Marshal(Capture(input, ModeFull))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("capture output diverged:\n%s\n%s", first, next)
		}
	}
}
