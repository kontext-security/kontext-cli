package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalise(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"v0.1.0", "0.1.0"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalise(tt.input); got != tt.want {
			t.Errorf("normalise(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewerThan(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.2.0", "0.1.0", true},
		{"1.0.0", "0.9.9", true},
		{"0.1.1", "0.1.0", true},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.2.0", false},
		{"0.1.0", "0.1.1", false},
		{"2.0.0", "1.99.99", true},
		{"0.2.0-rc.1", "0.1.0", true},
		{"not-semver", "0.1.0", false},
		{"0.1.0", "not-semver", false},
		{"foo", "bar", false},
	}
	for _, tt := range tests {
		if got := newerThan(tt.a, tt.b); got != tt.want {
			t.Errorf("newerThan(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
		ok    bool
	}{
		{"1.2.3", [3]int{1, 2, 3}, true},
		{"0.1.0", [3]int{0, 1, 0}, true},
		{"10.20.30", [3]int{10, 20, 30}, true},
		{"1.2.3-rc.1", [3]int{1, 2, 3}, true},
		{"1.2", [3]int{}, false},
		{"abc", [3]int{}, false},
		{"1.2.x", [3]int{}, false},
		{"", [3]int{}, false},
	}
	for _, tt := range tests {
		got, ok := parseSemver(tt.input)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseSemver(%q) = %v, %v; want %v, %v", tt.input, got, ok, tt.want, tt.ok)
		}
	}
}

func TestReadWriteCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "version.json")

	// No file yet.
	if _, ok := readCache(path); ok {
		t.Fatal("expected cache miss on empty path")
	}

	// Write and read back.
	writeCache(path, "0.2.0")
	got, ok := readCache(path)
	if !ok || got != "0.2.0" {
		t.Fatalf("readCache() = %q, %v; want %q, true", got, ok, "0.2.0")
	}

	// Expired cache.
	data, _ := json.Marshal(cachedVersion{
		LatestVersion: "0.2.0",
		CheckedAt:     time.Now().Add(-25 * time.Hour),
	})
	os.WriteFile(path, data, 0o644)
	if _, ok := readCache(path); ok {
		t.Fatal("expected cache miss on expired entry")
	}

	// Corrupt cache.
	os.WriteFile(path, []byte("not json"), 0o644)
	if _, ok := readCache(path); ok {
		t.Fatal("expected cache miss on corrupt file")
	}
}

func TestFetchLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("expected User-Agent header")
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
			t.Errorf("expected X-GitHub-Api-Version 2026-03-10, got %q", r.Header.Get("X-GitHub-Api-Version"))
		}
		json.NewEncoder(w).Encode(map[string]string{"tag_name": "v0.3.0"})
	}))
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	got := fetchLatest("0.1.0")
	if got != "0.3.0" {
		t.Errorf("fetchLatest() = %q, want %q", got, "0.3.0")
	}
}

func TestFetchLatestNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	if got := fetchLatest("0.1.0"); got != "" {
		t.Errorf("fetchLatest() on 403 = %q, want empty", got)
	}
}

func TestFetchLatestMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	if got := fetchLatest("0.1.0"); got != "" {
		t.Errorf("fetchLatest() on bad JSON = %q, want empty", got)
	}
}

func TestCheckSkipsDevVersion(t *testing.T) {
	check("dev")
	check("")
}

func TestCheckRespectsOptOut(t *testing.T) {
	t.Setenv("KONTEXT_NO_UPDATE_CHECK", "1")
	check("0.1.0")
}
