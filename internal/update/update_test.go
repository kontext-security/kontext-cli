package update

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		want  semver
		ok    bool
	}{
		{"1.2.3", semver{Major: 1, Minor: 2, Patch: 3}, true},
		{"0.1.0", semver{Major: 0, Minor: 1, Patch: 0}, true},
		{"10.20.30", semver{Major: 10, Minor: 20, Patch: 30}, true},
		{"1.2.3-rc.1", semver{Major: 1, Minor: 2, Patch: 3}, true},
		{"1.2", semver{}, false},
		{"abc", semver{}, false},
		{"1.2.x", semver{}, false},
		{"", semver{}, false},
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

	// Tampered cache with ANSI-escape payload that passes parseSemver
	// (the `-...` suffix is stripped by parseSemver before Atoi). readCache
	// must reject it via tagNamePattern so the payload never reaches the
	// terminal.
	tampered, _ := json.Marshal(cachedVersion{
		LatestVersion: "99.0.0-\x1b[31mRED",
		CheckedAt:     time.Now(),
	})
	os.WriteFile(path, tampered, 0o644)
	if got, ok := readCache(path); ok {
		t.Fatalf("expected cache miss on ANSI-injected version, got %q", got)
	}

	// Tampered cache with shell metacharacter payload.
	tampered2, _ := json.Marshal(cachedVersion{
		LatestVersion: "1.0.0; rm -rf /",
		CheckedAt:     time.Now(),
	})
	os.WriteFile(path, tampered2, 0o644)
	if got, ok := readCache(path); ok {
		t.Fatalf("expected cache miss on shell-metachar version, got %q", got)
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

func TestFetchLatestRejectsUnsafeTagName(t *testing.T) {
	tests := []struct {
		name    string
		tagName string
		want    string
	}{
		{"valid with v prefix", "v0.3.0", "0.3.0"},
		{"valid without v prefix", "0.3.0", "0.3.0"},
		{"valid pre-release", "v1.0.0-rc.1", "1.0.0-rc.1"},
		{"ansi escape injection", "v0.3.0\x1b[2K\x1b[G", ""},
		{"shell metacharacter", "v0.3.0; rm -rf /", ""},
		{"empty", "", ""},
		{"garbage", "not-a-version", ""},
		{"missing patch", "v1.2", ""},
		{"leading newline", "\nv0.3.0", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{"tag_name": tt.tagName})
			}))
			defer srv.Close()

			old := githubAPIBase
			githubAPIBase = srv.URL
			defer func() { githubAPIBase = old }()

			if got := fetchLatest("0.1.0"); got != tt.want {
				t.Errorf("fetchLatest(tag=%q) = %q, want %q", tt.tagName, got, tt.want)
			}
		})
	}
}

func TestWriteCachePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "version.json")
	writeCache(path, "0.2.0")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("cache perms = %o, want 0600", got)
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
	// Available should return "" for dev / empty versions.
	if v := Available("dev"); v != "" {
		t.Errorf("Available(dev) = %q, want empty", v)
	}
	if v := Available(""); v != "" {
		t.Errorf("Available(\"\") = %q, want empty", v)
	}
}

func TestCheckRespectsOptOut(t *testing.T) {
	t.Setenv("KONTEXT_NO_UPDATE_CHECK", "1")
	if v := Available("0.1.0"); v != "" {
		t.Errorf("Available() with opt-out = %q, want empty", v)
	}
}

func TestAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tag_name": "v0.5.0"})
	}))
	defer srv.Close()

	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	// Force cache miss by using a temp cache dir.
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	// Also set XDG_CACHE_HOME so os.UserCacheDir uses our temp dir on Linux.
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmpDir, "cache"))
	defer func() {
		// HOME is restored by t.Setenv automatically.
		_ = origHome
	}()

	got := Available("0.1.0")
	if got != "0.5.0" {
		t.Errorf("Available(0.1.0) = %q, want %q", got, "0.5.0")
	}

	// Same version → no update.
	got = Available("0.5.0")
	if got != "" {
		t.Errorf("Available(0.5.0) = %q, want empty", got)
	}
}

func TestClassifyBinaryPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/opt/homebrew/Cellar/kontext/0.3.0/bin/kontext", "brew"},
		{"/home/linuxbrew/.linuxbrew/Cellar/kontext/0.3.0/bin/kontext", "brew"},
		{"/usr/local/bin/kontext", "manual"},
		{"/Users/dev/go/bin/kontext", "manual"},
		{"/home/linuxbrew/bin/kontext", "brew"},
		{"/tmp/kontext", "manual"},
	}
	for _, tt := range tests {
		got := classifyBinaryPath(tt.path)
		if got != tt.want {
			t.Errorf("classifyBinaryPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestPromptAndUpgrade(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		method         string
		brewErr        error
		brewMissing    bool
		wantUpgraded   bool
		wantErr        bool
		outputContains string
		outputMissing  string
	}{
		{
			name:           "y + brew + success",
			input:          "y\n",
			method:         "brew",
			wantUpgraded:   true,
			outputContains: "Upgrade complete",
		},
		{
			name:           "Y (uppercase) + brew + success",
			input:          "Y\n",
			method:         "brew",
			wantUpgraded:   true,
			outputContains: "Upgrade complete",
		},
		{
			name:           "yes + brew + success",
			input:          "yes\n",
			method:         "brew",
			wantUpgraded:   true,
			outputContains: "Upgrade complete",
		},
		{
			name:          "n declines",
			input:         "n\n",
			method:        "brew",
			wantUpgraded:  false,
			outputMissing: "Upgrade complete",
		},
		{
			name:          "empty input (default) declines",
			input:         "\n",
			method:        "brew",
			wantUpgraded:  false,
			outputMissing: "Upgrade complete",
		},
		{
			name:           "y + manual method",
			input:          "y\n",
			method:         "manual",
			wantUpgraded:   false,
			outputContains: "To upgrade manually",
		},
		{
			name:           "y + brew + upgrade fails",
			input:          "y\n",
			method:         "brew",
			brewErr:        io.EOF, // any error
			wantUpgraded:   false,
			outputContains: "To upgrade manually",
		},
		{
			name:           "y + brew method but brew not on PATH",
			input:          "y\n",
			method:         "brew",
			brewMissing:    true,
			wantUpgraded:   false,
			outputContains: "To upgrade manually",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Override detectInstallMethodFn.
			oldDetect := detectInstallMethodFn
			detectInstallMethodFn = func() string { return tt.method }
			t.Cleanup(func() { detectInstallMethodFn = oldDetect })

			// Override brewUpgradeFn.
			oldBrew := brewUpgradeFn
			brewCalled := false
			brewUpgradeFn = func(ctx context.Context, brewPath string, in io.Reader, out io.Writer) error {
				brewCalled = true
				return tt.brewErr
			}
			t.Cleanup(func() { brewUpgradeFn = oldBrew })

			// Override lookPathFn. Default: return a fake absolute path so
			// PromptAndUpgrade proceeds to brewUpgradeFn. Tests can force a
			// LookPath failure via brewMissing.
			oldLookPath := lookPathFn
			if tt.brewMissing {
				lookPathFn = func(string) (string, error) { return "", exec.ErrNotFound }
			} else {
				lookPathFn = func(string) (string, error) { return "/opt/homebrew/bin/brew", nil }
			}
			t.Cleanup(func() { lookPathFn = oldLookPath })

			in := strings.NewReader(tt.input)
			var out bytes.Buffer

			upgraded, err := PromptAndUpgrade(in, &out, "0.1.0", "0.5.0")

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if upgraded != tt.wantUpgraded {
				t.Fatalf("upgraded = %v, want %v", upgraded, tt.wantUpgraded)
			}
			if tt.outputContains != "" && !strings.Contains(out.String(), tt.outputContains) {
				t.Errorf("output missing %q; got:\n%s", tt.outputContains, out.String())
			}
			if tt.outputMissing != "" && strings.Contains(out.String(), tt.outputMissing) {
				t.Errorf("output should not contain %q; got:\n%s", tt.outputMissing, out.String())
			}

			// Verify brew was not called when method is manual or user declined.
			if tt.method == "manual" && brewCalled {
				t.Error("brew upgrade should not be called for manual installs")
			}
			if (tt.input == "n\n" || tt.input == "\n") && brewCalled {
				t.Error("brew upgrade should not be called when user declined")
			}
			if tt.brewMissing && brewCalled {
				t.Error("brew upgrade should not be called when brew is not on PATH")
			}
		})
	}
}
