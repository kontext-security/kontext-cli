package githubpolicy

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const gitContextTimeout = 500 * time.Millisecond

// GitContextFromCWD derives the current branch and configured remotes from
// the session working directory. This stands in for the toolInput.kontext.git
// enrichment the cloud classifier receives.
func GitContextFromCWD(cwd string) GitContext {
	if strings.TrimSpace(cwd) == "" {
		return GitContext{}
	}
	context := GitContext{RemoteByName: map[string]string{}}
	if branch := gitOutput(cwd, "rev-parse", "--abbrev-ref", "HEAD"); branch != "HEAD" {
		context.Branch = branch
	}
	for _, line := range strings.Split(gitOutput(cwd, "config", "--get-regexp", `^remote\..*\.url$`), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(fields[0], "remote."), ".url")
		if name == "" {
			continue
		}
		context.RemoteByName[name] = fields[1]
	}
	return context
}

func gitOutput(cwd string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), gitContextTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", cwd}, args...)...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
