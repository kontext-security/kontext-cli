package endpointconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const identityFixturePath = "testdata/portable/v1/identity-v1.json"

// Update only when deliberately revising the portable fixture bytes.
const identityFixtureSHA256 = "c2f4f46040cf3dcbfa0599f33ad78874ebb675f76c2cb44c2fee3672bd0d4f5a"

type identityFixture struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	IdentityDomain string                  `json:"identityDomain"`
	Vectors        []identityFixtureVector `json:"vectors"`
}

type identityFixtureVector struct {
	Name            string `json:"name"`
	ResponseVersion int    `json:"responseVersion"`
	Config          Config `json:"config"`
	Preimage        string `json:"preimage"`
	ConfigIdentity  string `json:"configIdentity"`
}

func TestPortableIdentityFixture(t *testing.T) {
	data, err := os.ReadFile(identityFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != identityFixtureSHA256 {
		t.Fatalf("fixture SHA-256 = %s, want %s", got, identityFixtureSHA256)
	}
	var fixture identityFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "endpoint-config-identity-fixture-v1" || fixture.IdentityDomain != identityDomain {
		t.Fatalf("fixture metadata = %#v", fixture)
	}
	if len(fixture.Vectors) != 3 {
		t.Fatalf("fixture vector count = %d, want 3", len(fixture.Vectors))
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.ResponseVersion != ResponseVersion {
				t.Fatalf("responseVersion = %d", vector.ResponseVersion)
			}
			identity, err := ComputeIdentity(vector.Config)
			if err != nil {
				t.Fatal(err)
			}
			if identity != vector.ConfigIdentity {
				t.Fatalf("ComputeIdentity() = %s, want %s", identity, vector.ConfigIdentity)
			}
			preimage, err := json.Marshal([]any{identityDomain, ResponseVersion, string(vector.Config.PayloadCaptureMode)})
			if err != nil {
				t.Fatal(err)
			}
			if string(preimage) != vector.Preimage {
				t.Fatalf("preimage = %s, want %s", preimage, vector.Preimage)
			}
		})
	}
}
