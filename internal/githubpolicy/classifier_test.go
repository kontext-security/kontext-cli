package githubpolicy

import (
	"reflect"
	"testing"
)

func classifyBash(t *testing.T, command string, context GitContext) []ProviderAction {
	t.Helper()
	return ClassifyProviderActions("Bash", map[string]any{"command": command}, func() GitContext {
		return context
	})
}

func projectContext() GitContext {
	return GitContext{
		Branch: "feature/x",
		RemoteByName: map[string]string{
			"origin":   "git@github.com:acme/api.git",
			"upstream": "https://github.com/acme-upstream/api.git",
		},
	}
}

func TestClassifyGitPush(t *testing.T) {
	cases := []struct {
		command string
		want    []ProviderAction
	}{
		{
			command: "git push origin main",
			want:    []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "main"}},
		},
		{
			command: "git push origin local:refs/heads/release",
			want:    []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "release"}},
		},
		{
			// No refspec: falls back to the current branch.
			command: "git push origin",
			want:    []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "feature/x"}},
		},
		{
			// --tags push has no single branch.
			command: "git push --tags origin",
			want:    []ProviderAction{{Action: "github.repo.write", Resource: "acme/api"}},
		},
		{
			command: "git push upstream main",
			want:    []ProviderAction{{Action: "github.repo.write", Resource: "acme-upstream/api", BranchOrRef: "main"}},
		},
		{
			command: "git fetch origin main",
			want:    []ProviderAction{{Action: "github.repo.read", Resource: "acme/api", BranchOrRef: "main"}},
		},
		{
			command: "git clone https://github.com/acme/api.git",
			want:    []ProviderAction{{Action: "github.repo.read", Resource: "acme/api"}},
		},
	}
	for _, testCase := range cases {
		got := classifyBash(t, testCase.command, projectContext())
		if !reflect.DeepEqual(got, testCase.want) {
			t.Errorf("classify(%q) = %+v, want %+v", testCase.command, got, testCase.want)
		}
	}
}

func TestClassifyGitWithoutGithubRemoteIsNotProviderAction(t *testing.T) {
	context := GitContext{Branch: "main", RemoteByName: map[string]string{"origin": "git@gitlab.com:acme/api.git"}}
	if got := classifyBash(t, "git push origin main", context); got != nil {
		t.Fatalf("classify() = %+v, want nil for non-GitHub remote", got)
	}
	// Local-only git commands never classify.
	if got := classifyBash(t, "git status", projectContext()); got != nil {
		t.Fatalf("classify(git status) = %+v, want nil", got)
	}
}

func TestClassifyGhCommands(t *testing.T) {
	cases := []struct {
		command string
		want    []ProviderAction
	}{
		{"gh pr create --title x", []ProviderAction{{Action: "github.pr.write", Resource: "acme/api"}}},
		{"gh pr view 42", []ProviderAction{{Action: "github.pr.read", Resource: "acme/api"}}},
		{"gh pr merge 42 -R acme/web", []ProviderAction{{Action: "github.pr.write", Resource: "acme/web"}}},
		{"gh issue list --repo=acme/web", []ProviderAction{{Action: "github.issue.read", Resource: "acme/web"}}},
		{"gh issue comment 7", []ProviderAction{{Action: "github.issue.write", Resource: "acme/api"}}},
		{"gh repo view acme/api", []ProviderAction{{Action: "github.repo.read", Resource: "acme/api"}}},
		{"gh repo delete acme/api", []ProviderAction{{Action: "github.repo.write", Resource: "acme/api"}}},
		{"gh workflow run deploy.yml", []ProviderAction{{Action: "github.api.write", Resource: "acme/api"}}},
		{"gh workflow view deploy.yml", []ProviderAction{{Action: "github.api.read", Resource: "acme/api"}}},
		{"gh release create v1.0.0", []ProviderAction{{Action: "github.api.write", Resource: "acme/api"}}},
		{"gh release view v1.0.0", []ProviderAction{{Action: "github.api.read", Resource: "acme/api"}}},
		{"gh secret set TOKEN --body x", []ProviderAction{{Action: "github.api.write", Resource: "acme/api"}}},
		{"gh auth status", []ProviderAction{{Action: "github.api.read", Resource: "acme/api"}}},
		{"gh unknown subcommand", []ProviderAction{{Action: "github.api.write", Resource: "acme/api"}}},
	}
	for _, testCase := range cases {
		got := classifyBash(t, testCase.command, projectContext())
		if !reflect.DeepEqual(got, testCase.want) {
			t.Errorf("classify(%q) = %+v, want %+v", testCase.command, got, testCase.want)
		}
	}
}

func TestClassifyGhAPIHeuristic(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"gh api repos/acme/api/pulls", "github.api.read"},
		{"gh api -X POST repos/acme/api/pulls", "github.api.write"},
		{"gh api --method=DELETE repos/acme/api", "github.api.write"},
		{"gh api repos/acme/api/issues -f title=hello", "github.api.write"},
		{"gh api repos/acme/api/issues -F title=@file", "github.api.write"},
		{"gh api repos/acme/api/issues --raw-field title=x", "github.api.write"},
		{"gh api graphql --input mutation.json", "github.api.write"},
		// Unprovable method defaults to write.
		{"gh api -X \"$METHOD\" repos/acme/api", "github.api.write"},
		{"gh api -X GET repos/acme/api", "github.api.read"},
	}
	for _, testCase := range cases {
		got := classifyBash(t, testCase.command, projectContext())
		if len(got) != 1 || got[0].Action != testCase.want {
			t.Errorf("classify(%q) = %+v, want action %s", testCase.command, got, testCase.want)
		}
	}
}

func TestClassifyHTTPAndWebFetch(t *testing.T) {
	got := classifyBash(t, "curl https://api.github.com/repos/acme/api", GitContext{})
	if len(got) != 1 || got[0].Action != "github.api.read" {
		t.Fatalf("curl GET = %+v, want github.api.read", got)
	}
	got = classifyBash(t, "curl -X POST https://api.github.com/repos/acme/api/issues -d '{}'", GitContext{})
	if len(got) != 1 || got[0].Action != "github.api.write" {
		t.Fatalf("curl POST = %+v, want github.api.write", got)
	}
	got = ClassifyProviderActions("WebFetch", map[string]any{"url": "https://github.com/acme/api/pull/1"}, nil)
	if len(got) != 1 || got[0].Action != "github.api.read" {
		t.Fatalf("WebFetch = %+v, want github.api.read", got)
	}
	if got := ClassifyProviderActions("WebFetch", map[string]any{"url": "https://example.com"}, nil); got != nil {
		t.Fatalf("WebFetch non-GitHub = %+v, want nil", got)
	}
}

func TestClassifyChainedAndWrappedCommands(t *testing.T) {
	// add/commit stay local; only the push segment reaches GitHub.
	got := classifyBash(t, "git add -A && git commit -m x && git push origin main", projectContext())
	want := []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "main"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chained = %+v, want %+v", got, want)
	}

	got = classifyBash(t, `bash -c "git push origin main"`, projectContext())
	if !reflect.DeepEqual(got, []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "main"}}) {
		t.Fatalf("bash -c wrapped = %+v", got)
	}

	got = classifyBash(t, "sudo gh pr merge 42 -R acme/web", projectContext())
	if !reflect.DeepEqual(got, []ProviderAction{{Action: "github.pr.write", Resource: "acme/web"}}) {
		t.Fatalf("sudo wrapped = %+v", got)
	}
}

func TestClassifyNonGithubCommandsAreIgnored(t *testing.T) {
	for _, command := range []string{"ls -la", "npm test", "curl https://example.com"} {
		if got := classifyBash(t, command, projectContext()); got != nil {
			t.Errorf("classify(%q) = %+v, want nil", command, got)
		}
	}
	if got := ClassifyProviderActions("Read", map[string]any{"file_path": "/tmp/x"}, nil); got != nil {
		t.Fatalf("Read tool = %+v, want nil", got)
	}
}

func TestClassifyGitImplicitRemoteDefaultsToOrigin(t *testing.T) {
	cases := []struct {
		command string
		want    []ProviderAction
	}{
		{
			command: "git push",
			want:    []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "feature/x"}},
		},
		{
			command: "git pull",
			want:    []ProviderAction{{Action: "github.repo.read", Resource: "acme/api", BranchOrRef: "feature/x"}},
		},
		{
			command: "git fetch",
			want:    []ProviderAction{{Action: "github.repo.read", Resource: "acme/api", BranchOrRef: "feature/x"}},
		},
	}
	for _, testCase := range cases {
		got := classifyBash(t, testCase.command, projectContext())
		if !reflect.DeepEqual(got, testCase.want) {
			t.Errorf("classify(%q) = %+v, want %+v", testCase.command, got, testCase.want)
		}
	}
	// No origin remote configured: nothing to evaluate.
	if got := classifyBash(t, "git push", GitContext{Branch: "main"}); got != nil {
		t.Fatalf("classify(git push) without remotes = %+v, want nil", got)
	}
}

func TestClassifyGitCloneDoesNotInheritCwdBranch(t *testing.T) {
	got := classifyBash(t, "git clone https://github.com/acme/api.git", projectContext())
	want := []ProviderAction{{Action: "github.repo.read", Resource: "acme/api"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clone = %+v, want no branch from cwd", got)
	}
	got = classifyBash(t, "git clone -b release https://github.com/acme/api.git", projectContext())
	want = []ProviderAction{{Action: "github.repo.read", Resource: "acme/api", BranchOrRef: "release"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clone -b = %+v, want explicit branch", got)
	}
}

func TestClassifyGhRepoPositionalArgument(t *testing.T) {
	// The positional repo argument names the target even when the cwd is a
	// different repository.
	got := classifyBash(t, "gh repo delete acme/admin --yes", projectContext())
	want := []ProviderAction{{Action: "github.repo.write", Resource: "acme/admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gh repo delete = %+v, want %+v", got, want)
	}
	got = classifyBash(t, "gh repo clone https://github.com/acme/admin.git", projectContext())
	want = []ProviderAction{{Action: "github.repo.read", Resource: "acme/admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gh repo clone = %+v, want %+v", got, want)
	}
}

func TestClassifyGhAPIEndpointRepo(t *testing.T) {
	cases := []struct {
		command string
		want    ProviderAction
	}{
		{
			command: "gh api repos/acme/admin/issues -f title=x",
			want:    ProviderAction{Action: "github.api.write", Resource: "acme/admin"},
		},
		{
			command: "gh api /repos/acme/admin/pulls",
			want:    ProviderAction{Action: "github.api.read", Resource: "acme/admin"},
		},
		{
			command: "gh api https://api.github.com/repos/acme/admin",
			want:    ProviderAction{Action: "github.api.read", Resource: "acme/admin"},
		},
		{
			// Placeholders resolve through -R, not the literal path.
			command: "gh api repos/{owner}/{repo}/issues -R acme/web",
			want:    ProviderAction{Action: "github.api.read", Resource: "acme/web"},
		},
		{
			// Non-repos endpoints carry no repository: cwd fallback applies.
			command: "gh api orgs/acme/teams",
			want:    ProviderAction{Action: "github.api.read", Resource: "acme/api"},
		},
		{
			// Value flags before the endpoint must not shift the positional.
			command: "gh api -X DELETE repos/acme/admin/issues/1",
			want:    ProviderAction{Action: "github.api.write", Resource: "acme/admin"},
		},
		{
			command: "gh api --method=DELETE repos/acme/admin/issues/1",
			want:    ProviderAction{Action: "github.api.write", Resource: "acme/admin"},
		},
		{
			command: "gh api -H 'Accept: application/vnd.github+json' repos/acme/admin/pulls",
			want:    ProviderAction{Action: "github.api.read", Resource: "acme/admin"},
		},
		{
			command: "gh api --input payload.json repos/acme/admin/issues",
			want:    ProviderAction{Action: "github.api.write", Resource: "acme/admin"},
		},
		{
			command: "gh api --paginate repos/acme/admin/pulls",
			want:    ProviderAction{Action: "github.api.read", Resource: "acme/admin"},
		},
	}
	for _, testCase := range cases {
		got := classifyBash(t, testCase.command, projectContext())
		if len(got) != 1 || got[0] != testCase.want {
			t.Errorf("classify(%q) = %+v, want %+v", testCase.command, got, testCase.want)
		}
	}
}

func TestClassifyURLResources(t *testing.T) {
	got := classifyBash(t, "curl -X DELETE https://api.github.com/repos/acme/admin/issues/1", GitContext{})
	want := []ProviderAction{{Action: "github.api.write", Resource: "acme/admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("curl api = %+v, want %+v", got, want)
	}
	// Non-repos API paths have no repository to anchor on.
	got = classifyBash(t, "curl https://api.github.com/orgs/acme/teams", GitContext{})
	want = []ProviderAction{{Action: "github.api.read"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("curl orgs = %+v, want no resource", got)
	}
	got = ClassifyProviderActions("WebFetch", map[string]any{"url": "https://github.com/acme/admin/pull/1"}, nil)
	want = []ProviderAction{{Action: "github.api.read", Resource: "acme/admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WebFetch = %+v, want %+v", got, want)
	}
}

func TestClassifyGitCommitDoesNotReachGithub(t *testing.T) {
	// Mirrors the cloud classifier: commit/tag are local until pushed, so
	// without a github.com mention or a selected GitHub remote they do not
	// classify as provider actions.
	if got := classifyBash(t, "git commit -m 'msg'", projectContext()); got != nil {
		t.Fatalf("git commit = %+v, want nil", got)
	}
}

func TestClassifyScriptInput(t *testing.T) {
	got := ClassifyProviderActions("Bash", map[string]any{"script": "git push origin main"}, func() GitContext {
		return projectContext()
	})
	want := []ProviderAction{{Action: "github.repo.write", Resource: "acme/api", BranchOrRef: "main"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("script input = %+v, want %+v", got, want)
	}
}

func TestClassifyGithubMCPTool(t *testing.T) {
	got := ClassifyProviderActions("mcp__github__get_pull_request", map[string]any{
		"owner":       "acme",
		"repo":        "admin",
		"pull_number": 42,
	}, nil)
	want := []ProviderAction{{Action: "github.pr.read", Resource: "acme/admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("github mcp get_pull_request = %+v, want %+v", got, want)
	}

	got = ClassifyProviderActions("mcp__github__merge_pull_request", map[string]any{"repository": "acme/admin"}, nil)
	want = []ProviderAction{{Action: "github.pr.write", Resource: "acme/admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("github mcp merge_pull_request = %+v, want %+v", got, want)
	}
}

func TestClassifyGitDashCUsesTargetContext(t *testing.T) {
	contexts := map[string]GitContext{
		"/work/current": projectContext(),
		"/work/other-repo": {
			Branch: "main",
			RemoteByName: map[string]string{
				"origin": "git@github.com:acme/admin.git",
			},
		},
	}
	got := ClassifyProviderActionsWithCWD("Bash", map[string]any{"command": "git -C ../other-repo push"}, "/work/current", func(cwd string) GitContext {
		return contexts[cwd]
	})
	want := []ProviderAction{{Action: "github.repo.write", Resource: "acme/admin", BranchOrRef: "main"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("git -C push = %+v, want %+v", got, want)
	}
}
