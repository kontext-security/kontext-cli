// Package update checks GitHub for newer CLI releases.
package update

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

const (
	repo          = "kontext-security/kontext-cli"
	cacheTTL      = 24 * time.Hour
	brewUpgradeTO = 120 * time.Second
)

// tagNamePattern restricts GitHub release tag_name values to strict semver
// (with optional "v" prefix and pre-release suffix). This guards against
// ANSI-escape injection or shell-metacharacter payloads from a MITM'd or
// poisoned GitHub response being rendered to the terminal or cached.
var tagNamePattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._-]+)?$`)

// githubAPIBase is the base URL for GitHub API requests. Tests override this
// to point at an httptest server.
var githubAPIBase = "https://api.github.com"

// brewUpgradeFn is the function that runs the brew upgrade command.
// Tests override this to avoid actually calling brew.
var brewUpgradeFn = runBrewUpgrade

// detectInstallMethodFn is the function that detects the install method.
// Tests override this to control the result.
var detectInstallMethodFn = detectInstallMethod

// lookPathFn resolves an executable name on PATH. Tests override this to
// simulate brew being missing even when install-method detection says "brew".
var lookPathFn = exec.LookPath

type cachedVersion struct {
	LatestVersion string    `json:"latest_version"`
	CheckedAt     time.Time `json:"checked_at"`
}

type semver struct {
	Major int
	Minor int
	Patch int
}

// CheckAsync spawns a background goroutine that checks for a newer release.
// It prints a one-liner to stderr if an update is available, and does nothing
// on any error. The check is fully fire-and-forget — it never blocks the caller.
func CheckAsync(currentVersion string) {
	go func() {
		if v := Available(currentVersion); v != "" {
			PrintNotification(os.Stderr, currentVersion, v)
		}
	}()
}

// Available returns the latest release version if one newer than currentVersion
// exists, else empty string. Respects the 24h cache and KONTEXT_NO_UPDATE_CHECK.
// Blocks for up to 3s on cache miss (HTTP fetch with 3s timeout).
func Available(currentVersion string) string {
	if currentVersion == "" || currentVersion == "dev" {
		return ""
	}
	if os.Getenv("KONTEXT_NO_UPDATE_CHECK") != "" {
		return ""
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	cacheFile := filepath.Join(cacheDir, "kontext", "version.json")

	latest, ok := readCache(cacheFile)
	if !ok {
		latest = fetchLatest(currentVersion)
		if latest == "" {
			return ""
		}
		writeCache(cacheFile, latest)
	}

	if newerThan(latest, normalise(currentVersion)) {
		return latest
	}
	return ""
}

// PrintNotification writes the passive "update available" one-liner to w.
func PrintNotification(w io.Writer, currentVersion, latestVersion string) {
	fmt.Fprintf(w,
		"\n⚠ A new version of kontext is available: %s → %s\n"+
			"  See: https://github.com/%s/releases/tag/v%s\n\n",
		currentVersion, latestVersion, repo, latestVersion)
}

// PromptAndUpgrade prompts the user "Update now? [y/N] " on out, reads a single
// line from in, and on "y"/"yes" (case-insensitive) attempts to run the upgrade.
// Returns (true, nil) when a brew upgrade command ran successfully — the caller
// should exit so the user can re-invoke. Returns (false, nil) when the user
// declined, the install method is manual, or brew is not on PATH (in which case
// manual instructions are printed to out). Returns (false, err) only for
// truly unexpected errors (e.g. stdin read error).
func PromptAndUpgrade(in io.Reader, out io.Writer, currentVersion, latestVersion string) (bool, error) {
	PrintNotification(out, currentVersion, latestVersion)

	fmt.Fprint(out, "Update now? [y/N] ")

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, err
		}
		// EOF with no input — treat as "no".
		return false, nil
	}

	answer := strings.TrimSpace(scanner.Text())
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		return false, nil
	}

	method := detectInstallMethodFn()
	if method != "brew" {
		printManualInstructions(out, latestVersion)
		return false, nil
	}

	brewPath, err := lookPathFn("brew")
	if err != nil {
		printManualInstructions(out, latestVersion)
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), brewUpgradeTO)
	defer cancel()

	if err := brewUpgradeFn(ctx, brewPath, in, out); err != nil {
		fmt.Fprintf(out, "\nbrew upgrade failed: %v\n", err)
		printManualInstructions(out, latestVersion)
		return false, nil
	}

	fmt.Fprintln(out, "✓ Upgrade complete. Re-run: kontext start")
	return true, nil
}

func printManualInstructions(w io.Writer, latestVersion string) {
	fmt.Fprintf(w,
		"\nTo upgrade manually:\n"+
			"  brew upgrade kontext-security/tap/kontext      # if installed via Homebrew\n"+
			"  or download v%s from https://github.com/%s/releases/tag/v%s\n",
		latestVersion, repo, latestVersion)
}

// classifyBinaryPath returns "brew" if the path looks like a Homebrew-managed
// binary, otherwise "manual".
func classifyBinaryPath(path string) string {
	if strings.Contains(path, "/Cellar/") || strings.Contains(path, "/linuxbrew/") {
		return "brew"
	}
	return "manual"
}

func detectInstallMethod() string {
	exe, err := os.Executable()
	if err != nil {
		return "manual"
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "manual"
	}
	return classifyBinaryPath(resolved)
}

func runBrewUpgrade(ctx context.Context, brewPath string, in io.Reader, out io.Writer) error {
	cmd := exec.CommandContext(ctx, brewPath, "upgrade", "kontext-security/tap/kontext")
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
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
	return aParts.greaterThan(bParts)
}

func (v semver) greaterThan(other semver) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}

func parseSemver(v string) (semver, bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return semver{}, false
	}
	var out semver
	for i, p := range parts {
		// Strip pre-release suffix (e.g. "1-rc.1" → "1")
		if idx := strings.IndexByte(p, '-'); idx != -1 {
			p = p[:idx]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return semver{}, false
		}
		switch i {
		case 0:
			out.Major = n
		case 1:
			out.Minor = n
		case 2:
			out.Patch = n
		}
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
	if !tagNamePattern.MatchString(c.LatestVersion) {
		debugf("rejected cached version %q: does not match strict semver", c.LatestVersion)
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
	_ = os.WriteFile(path, data, 0o600)
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
		debugf("fetch error: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		debugf("fetch non-200: %d", resp.StatusCode)
		return ""
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		debugf("decode error: %v", err)
		return ""
	}
	if !tagNamePattern.MatchString(release.TagName) {
		debugf("rejected tag_name %q: does not match strict semver", release.TagName)
		return ""
	}
	return normalise(release.TagName)
}

func debugf(format string, args ...any) {
	if !diagnostic.EnabledFromEnv() {
		return
	}
	fmt.Fprintf(os.Stderr, "[kontext update] "+format+"\n", args...)
}

func normalise(v string) string {
	return strings.TrimPrefix(v, "v")
}
