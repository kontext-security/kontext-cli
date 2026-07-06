package payloadcapture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Mode controls how much of a tool payload is captured. It is org policy,
// resolved elsewhere; this package only executes it.
type Mode string

const (
	// ModeOmitted records that a payload existed and how large it was,
	// without content and without a fingerprint.
	ModeOmitted Mode = "omitted"
	// ModeSummary is the default: no captured payload record is produced.
	ModeSummary Mode = "summary"
	// ModeFull captures the redacted payload, truncating oversized content.
	ModeFull Mode = "full"
)

// FailureReason explains a capture_failed record. Failures never carry
// payload content.
type FailureReason string

const (
	ReasonSerializationError   FailureReason = "serialization_error"
	ReasonRedactionError       FailureReason = "redaction_error"
	ReasonSizePrecheckExceeded FailureReason = "size_precheck_exceeded"
	ReasonInvalidPayload       FailureReason = "invalid_payload"
)

const (
	// MaxPayloadBytes caps the serialized captured payload record. The fit
	// test applies to the WHOLE serialized record, not the content alone:
	// JSON escaping can inflate content substantially.
	MaxPayloadBytes = 64_000
	// InputHardCapBytes bounds the raw canonical input this package will
	// process at all.
	InputHardCapBytes = 1 << 20
)

const (
	modeFullTruncated = "full_truncated"
	modeFailed        = "capture_failed"
)

// Payload is one captured tool payload record. Exactly one of the shapes
// implied by Mode is serialized; illegal field combinations are not
// representable on the wire (see MarshalJSON).
type Payload struct {
	Mode             string
	Value            map[string]any
	Preview          string
	Redacted         bool
	Reason           FailureReason
	SourceSha256     string
	SourceByteLength int
	StoredSha256     string
	StoredByteLength int

	hasSourceCommitment bool
}

// MarshalJSON emits only the fields that belong to the record's mode.
func (p Payload) MarshalJSON() ([]byte, error) {
	record := map[string]any{"mode": p.Mode}
	switch p.Mode {
	case string(ModeOmitted):
		record["sourceByteLength"] = p.SourceByteLength
	case string(ModeFull):
		record["value"] = p.Value
		p.fillContentFields(record)
	case modeFullTruncated:
		record["preview"] = p.Preview
		p.fillContentFields(record)
	case modeFailed:
		record["reason"] = p.Reason
		if p.hasSourceCommitment {
			record["sourceSha256"] = p.SourceSha256
			record["sourceByteLength"] = p.SourceByteLength
		}
	default:
		return nil, fmt.Errorf("payloadcapture: unknown mode %q", p.Mode)
	}
	return json.Marshal(record)
}

func (p Payload) fillContentFields(record map[string]any) {
	record["redacted"] = p.Redacted
	record["redactorVersion"] = RedactorVersion
	record["sourceSha256"] = p.SourceSha256
	record["sourceByteLength"] = p.SourceByteLength
	record["storedSha256"] = p.StoredSha256
	record["storedByteLength"] = p.StoredByteLength
}

// Capture turns a decoded tool payload into a captured payload record.
//
// It returns nil when nothing should be recorded: empty input, summary mode,
// or an unrecognized mode (unknown never means "send content"). Every error
// path returns a capture_failed record and never any input content.
func Capture(input map[string]any, mode Mode) *Payload {
	if len(input) == 0 {
		return nil
	}
	if mode != ModeOmitted && mode != ModeFull {
		return nil
	}

	canonical, err := CanonicalJSON(input)
	if err != nil {
		return failedPayload(ReasonSerializationError)
	}
	if len(canonical) > InputHardCapBytes {
		return failedPayload(ReasonSizePrecheckExceeded)
	}

	sourceSha := sha256Hex(canonical)
	sourceLen := len(canonical)

	if mode == ModeOmitted {
		return &Payload{
			Mode:             string(ModeOmitted),
			SourceByteLength: sourceLen,
		}
	}

	return captureFull(input, sourceSha, sourceLen)
}

func captureFull(input map[string]any, sourceSha string, sourceLen int) (payload *Payload) {
	// Redaction runs on untrusted content; any panic must degrade to a
	// content-free failure record instead of escaping with raw data.
	defer func() {
		if recover() != nil {
			payload = failedWithCommitment(ReasonRedactionError, sourceSha, sourceLen)
		}
	}()

	redactedValue, changed := RedactJSON(input)
	redactedCanonical, err := CanonicalJSON(redactedValue)
	if err != nil {
		return failedWithCommitment(ReasonRedactionError, sourceSha, sourceLen)
	}

	full := &Payload{
		Mode:             string(ModeFull),
		Value:            redactedValue,
		Redacted:         changed,
		SourceSha256:     sourceSha,
		SourceByteLength: sourceLen,
		StoredSha256:     sha256Hex(redactedCanonical),
		StoredByteLength: len(redactedCanonical),
	}
	if size, err := serializedSize(full); err == nil && size <= MaxPayloadBytes {
		return full
	}

	return truncatedPayload(redactedCanonical, changed, sourceSha, sourceLen)
}

// truncatedPayload cuts the redacted canonical string so that the WHOLE
// serialized record fits MaxPayloadBytes. The cut lands on a UTF-8 boundary
// and is deterministic: identical input, mode, and ruleset version produce
// identical bytes.
func truncatedPayload(redactedCanonical []byte, changed bool, sourceSha string, sourceLen int) *Payload {
	marker := fmt.Sprintf("[truncated %d bytes total]", len(redactedCanonical))

	build := func(cut int) *Payload {
		preview := string(redactedCanonical[:cut]) + marker
		return &Payload{
			Mode:             modeFullTruncated,
			Preview:          preview,
			Redacted:         changed,
			SourceSha256:     sourceSha,
			SourceByteLength: sourceLen,
			StoredSha256:     sha256Hex([]byte(preview)),
			StoredByteLength: len(preview),
		}
	}

	fits := func(cut int) bool {
		size, err := serializedSize(build(cut))
		return err == nil && size <= MaxPayloadBytes
	}

	low, high, best := 0, len(redactedCanonical), 0
	for low <= high {
		mid := utf8Boundary(redactedCanonical, (low+high)/2)
		if fits(mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	return build(utf8Boundary(redactedCanonical, best))
}

// utf8Boundary moves cut backwards until it does not split a multi-byte rune.
func utf8Boundary(data []byte, cut int) int {
	for cut > 0 && cut < len(data) && !utf8.RuneStart(data[cut]) {
		cut--
	}
	return cut
}

// serializedSize measures the record the way its consumers do: standard JSON
// without HTML escaping. encoding/json escapes <, >, and & by default, which
// would overstate the size against the shared byte cap.
func serializedSize(payload *Payload) (int, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return 0, err
	}
	return len(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

func failedPayload(reason FailureReason) *Payload {
	return &Payload{Mode: modeFailed, Reason: reason}
}

func failedWithCommitment(reason FailureReason, sourceSha string, sourceLen int) *Payload {
	return &Payload{
		Mode:                modeFailed,
		Reason:              reason,
		SourceSha256:        sourceSha,
		SourceByteLength:    sourceLen,
		hasSourceCommitment: true,
	}
}
