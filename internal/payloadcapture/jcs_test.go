package payloadcapture

import (
	"encoding/json"
	"testing"
)

type jcsVector struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Input           json.RawMessage `json:"input"`
	CanonicalString string          `json:"canonicalString"`
	Sha256Hex       string          `json:"sha256Hex"`
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
