package payloadcapture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type jcsVector struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Input           json.RawMessage `json:"input"`
	CanonicalString string          `json:"canonicalString"`
	Sha256Hex       string          `json:"sha256Hex"`
}

func loadTestdata(t *testing.T, name string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
}

// decodeUseNumber mirrors how hook payloads are decoded elsewhere in this
// codebase: numbers arrive as json.Number, and canonicalization must still
// produce the shared byte-exact output.
func decodeUseNumber(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	return value
}

func TestCanonicalJSONMatchesSharedVectors(t *testing.T) {
	t.Parallel()

	var vectors []jcsVector
	loadTestdata(t, "jcs-vectors.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no jcs vectors loaded")
	}

	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			canonical, err := CanonicalJSON(decodeUseNumber(t, vector.Input))
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if got := string(canonical); got != vector.CanonicalString {
				t.Fatalf("canonical mismatch:\n got: %q\nwant: %q", got, vector.CanonicalString)
			}
			if got := sha256Hex(canonical); got != vector.Sha256Hex {
				t.Fatalf("sha256 mismatch: got %s want %s", got, vector.Sha256Hex)
			}
		})
	}
}
