package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchFromBackend(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/policy/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"policyEnabled": true})
	})
	mux.HandleFunc("GET /api/v1/policy/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{"action": "allow", "scope": "tool", "level": "org", "toolName": "Read"},
			{"action": "deny", "scope": "tool", "level": "org", "toolName": "Bash"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	engine, err := Fetch(context.Background(), srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	allowed, _ := engine.Evaluate("Read", "")
	if !allowed {
		t.Error("Read should be allowed")
	}

	allowed, _ = engine.Evaluate("Bash", "")
	if allowed {
		t.Error("Bash should be denied")
	}
}

func TestFetchPolicyDisabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/policy/settings", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"policyEnabled": false})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	engine, err := Fetch(context.Background(), srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	allowed, _ := engine.Evaluate("Bash", "")
	if !allowed {
		t.Error("should allow everything when policy disabled")
	}
}
