package payloadcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/gowebpki/jcs"
)

// CanonicalJSON serializes a JSON value into its RFC 8785 (JCS) canonical
// form. Canonical bytes are the input to every payload fingerprint, so the
// output must be byte-identical across implementations; the vectors in
// testdata/jcs-vectors.json pin that behavior.
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
