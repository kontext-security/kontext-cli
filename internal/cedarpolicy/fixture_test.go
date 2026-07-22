package cedarpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

const getPolicyStateFixturePath = "testdata/portable/v1/get-policy-states-v1.json"
const getPolicyStateFixtureSHA256 = "eaa1c01f0ab6f54db822894dc8038a5608ae0001aa0396b5402d2d3cc67caf26"

func TestPortableGetPolicyStateFixture(t *testing.T) {
	data, err := os.ReadFile(getPolicyStateFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != getPolicyStateFixtureSHA256 {
		t.Fatalf("fixture SHA-256 = %s, want %s", got, getPolicyStateFixtureSHA256)
	}
	var responses []StateResponse
	if err := json.Unmarshal(data, &responses); err != nil {
		t.Fatal(err)
	}
	got := make([]State, 0, len(responses))
	for _, response := range responses {
		if err := response.Validate(); err != nil {
			t.Fatalf("Validate(%q) error = %v", response.State, err)
		}
		got = append(got, response.State)
	}
	want := []State{
		StateNotModified,
		StateDisabled,
		StateNoActivePolicy,
		StatePrincipalUnavailable,
		StateUnsupportedVersion,
		StateUnauthorized,
		StateUnavailable,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture states = %v, want %v", got, want)
	}
}
