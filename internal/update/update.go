// Package update checks GitHub for newer CLI releases.
package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	repo     = "kontext-dev/kontext-cli"
	cacheTTL = 24 * time.Hour
)

type cachedVersion struct {
	LatestVersion string    `json:"latest_version"`
	CheckedAt     time.Time `json:"checked_at"`
}

// CheckAsync spawns a background goroutine that checks for a newer release.
// It prints a one-liner to stderr if an update is available, and does nothing
// on any error. The done channel is closed when the check completes.
func CheckAsync(currentVersion string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		check(currentVersion)
	}()
	return done
}

func check(currentVersion string) {
	if currentVersion == "" || currentVersion == "dev" {
		return
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	cacheFile := filepath.Join(cacheDir, "kontext", "version.json")

	latest, ok := readCache(cacheFile)
	if !ok {
		latest = fetchLatest()
		if latest == "" {
			return
		}
		writeCache(cacheFile, latest)
	}

	if latest != "" && latest != normalise(currentVersion) {
		fmt.Fprintf(os.Stderr,
			"\n⚠ A new version of kontext is available: %s → %s\n"+
				"  Update: gh release download %s --repo %s --pattern '*darwin_arm64*' --dir /tmp\n\n",
			currentVersion, latest, latest, repo)
	}
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
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	data, _ := json.Marshal(cachedVersion{
		LatestVersion: version,
		CheckedAt:     time.Now(),
	})
	_ = os.WriteFile(path, data, 0o644)
}

func fetchLatest() string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

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
