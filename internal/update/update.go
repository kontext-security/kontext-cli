// Package update checks GitHub for newer CLI releases.
package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	repo     = "kontext-dev/kontext-cli"
	cacheTTL = 24 * time.Hour
)

// githubAPIBase is the base URL for GitHub API requests. Tests override this
// to point at an httptest server.
var githubAPIBase = "https://api.github.com"

type cachedVersion struct {
	LatestVersion string    `json:"latest_version"`
	CheckedAt     time.Time `json:"checked_at"`
}

// CheckAsync spawns a background goroutine that checks for a newer release.
// It prints a one-liner to stderr if an update is available, and does nothing
// on any error. The check is fully fire-and-forget — it never blocks the caller.
func CheckAsync(currentVersion string) {
	go check(currentVersion)
}

func check(currentVersion string) {
	if currentVersion == "" || currentVersion == "dev" {
		return
	}
	if os.Getenv("KONTEXT_NO_UPDATE_CHECK") != "" {
		return
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	cacheFile := filepath.Join(cacheDir, "kontext", "version.json")

	latest, ok := readCache(cacheFile)
	if !ok {
		latest = fetchLatest(currentVersion)
		if latest == "" {
			return
		}
		writeCache(cacheFile, latest)
	}

	if newerThan(latest, normalise(currentVersion)) {
		fmt.Fprintf(os.Stderr,
			"\n⚠ A new version of kontext is available: %s → %s\n"+
				"  See: https://github.com/%s/releases/tag/v%s\n\n",
			currentVersion, latest, repo, latest)
	}
}

// newerThan returns true if version a is strictly newer than b.
// Both must be normalised (no "v" prefix). Returns false if either
// version is not a valid major.minor.patch triple.
func newerThan(a, b string) bool {
	aParts, aOK := parseSemver(a)
	bParts, bOK := parseSemver(b)
	if !aOK || !bOK {
		return false
	}
	for i := 0; i < 3; i++ {
		if aParts[i] != bParts[i] {
			return aParts[i] > bParts[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		// Strip pre-release suffix (e.g. "1-rc.1" → "1")
		if idx := strings.IndexByte(p, '-'); idx != -1 {
			p = p[:idx]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func readCache(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var c cachedVersion
	if err := json.Unmarshal(data, &c); err != nil {
		return "", false
	}
	if time.Since(c.CheckedAt) > cacheTTL {
		return "", false
	}
	return c.LatestVersion, true
}

func writeCache(path, version string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, _ := json.Marshal(cachedVersion{
		LatestVersion: version,
		CheckedAt:     time.Now(),
	})
	_ = os.WriteFile(path, data, 0o644)
}

func fetchLatest(currentVersion string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("%s/repos/%s/releases/latest", githubAPIBase, repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "kontext-cli/"+currentVersion)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ""
	}
	return normalise(release.TagName)
}

func normalise(v string) string {
	return strings.TrimPrefix(v, "v")
}
