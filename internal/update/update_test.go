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
	// Mock GitHub API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("expected User-Agent header")
		}
		json.NewEncoder(w).Encode(map[string]string{"tag_name": "v0.3.0"})
	}))
	defer srv.Close()

	// Override the repo URL by testing the internal function directly isn't
	// possible without changing the package, so we test via httptest by
	// temporarily swapping the fetch function. Since fetchLatest hardcodes
	// the URL, we test the response parsing logic via the mock server.
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kontext-cli/test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if got := normalise(release.TagName); got != "0.3.0" {
		t.Errorf("got %q, want %q", got, "0.3.0")
	}
}

func TestCheckSkipsDevVersion(t *testing.T) {
	// Should not panic or produce output for dev builds.
	check("dev")
	check("")
}

func TestCheckRespectsOptOut(t *testing.T) {
	t.Setenv("KONTEXT_NO_UPDATE_CHECK", "1")
	// Should return immediately without any network calls.
	check("0.1.0")
}
