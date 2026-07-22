package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	config := Config{PayloadCaptureMode: mode}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}
