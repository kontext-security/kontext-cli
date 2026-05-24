package server

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func TestNewServerWithOptionsRejectsInvalidPolicyConfig(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatalf("OpenStore(): %v", err)
	}
	defer store.Close()

	_, err = NewServerWithOptions(store, Options{
		PolicyConfig: policy.Config{
			Profile: policy.Profile("unknown-profile"),
		},
	})
	if err == nil {
		t.Fatalf("NewServerWithOptions() err = nil, want invalid policy config error")
	}
}
