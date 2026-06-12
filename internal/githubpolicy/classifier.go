package githubpolicy

import (
	"regexp"
	"strings"
)

// This classifier mirrors the cloud reference implementation in
// apps/api/src/agent-service/provider-action-classifier.ts so local dry-run
// decisions match what the cloud would decide for the same activity.
//
// Canonical action names emitted: github.repo.read|write, github.pr.read|write,
// github.issue.read|write, github.api.read|write. The release/workflow/secret/
// gist catalog buckets are not classified yet.
//
// Policy matching uses repo + branch + action only; file paths and API
// endpoint details are audit context.

// ProviderAction is one classified GitHub action extracted from a tool call.
type ProviderAction struct {
	// Action is the canonical action name, e.g. "github.pr.write".
	Action string
	// Resource is the repository slug "owner/repo" when derivable.
	Resource string
	// BranchOrRef is the branch or ref when derivable (push refspecs,
	// fetch/pull positionals, current branch fallback).
	BranchOrRef string
}

// GitContext carries repository context derived from the session working
// directory (current branch and configured remotes). It mirrors the
// toolInput.kontext.git enrichment the cloud classifier consumes.
type GitContext struct {
	Branch       string
	RemoteByName map[string]string
}

func (c GitContext) githubRemotes() []string {
	remotes := make([]string, 0, len(c.RemoteByName))
	// Prefer origin so the fallback repo is deterministic.
	if url, ok := c.RemoteByName["origin"]; ok && isGithubURL(url) {
		remotes = append(remotes, url)
	}
	for name, url := range c.RemoteByName {
		if name == "origin" || !isGithubURL(url) {
			continue
		}
		remotes = append(remotes, url)
	}
	return remotes
}

var githubHostRE = regexp.MustCompile(`(?i)(^|[\s"'(<])((https?://)?(api\.)?github\.com[/:]|(ssh://)?git@github\.com[:/])`)

// ClassifyProviderActions maps a tool invocation to canonical GitHub actions.
// gitContext is invoked lazily — only when a git command needs remote or
// branch resolution — because deriving it shells out to git.
func ClassifyProviderActions(toolName string, toolInput map[string]any, gitContext func() GitContext) []ProviderAction {
	if gitContext == nil {
		gitContext = func() GitContext { return GitContext{} }
	}
	switch strings.ToLower(toolName) {
	case "bash", "shell":
		command, _ := stringField(toolInput, "command")
		if command == "" {
			command, _ = stringField(toolInput, "cmd")
		}
		if command == "" {
			return nil
		}
		return classifyCommand(command, memoizedGitContext(gitContext))
	case "webfetch", "web_fetch":
		url, _ := stringField(toolInput, "url")
		if url != "" && isGithubURL(url) {
			return []ProviderAction{{Action: "github.api.read", Resource: normalizeGithubRepo(url)}}
		}
	}
	return nil
}

func memoizedGitContext(load func() GitContext) func() GitContext {
	var cached *GitContext
	return func() GitContext {
		if cached == nil {
			context := load()
			cached = &context
		}
		return *cached
	}
}

func classifyCommand(command string, gitContext func() GitContext) []ProviderAction {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil
	}
	var actions []ProviderAction
	for _, segment := range splitCommandSegments(trimmed) {
		invocation, args := commandInvocation(segment)
		if unwrapped, ok := unwrapShellLauncher(invocation, args); ok {
			actions = append(actions, classifyCommand(unwrapped, gitContext)...)
			continue
		}
		switch invocation {
		case "gh":
			actions = append(actions, classifyGhCommand(args, segment, gitContext))
			continue
		case "git":
			actions = append(actions, classifyGitCommand(args, segment, gitContext)...)
			continue
		case "curl", "wget", "http", "https", "httpie":
			if isGithubURL(segment) {
				actions = append(actions, ProviderAction{
					Action:   apiAction(commandLooksMutating(segment)),
					Resource: normalizeGithubRepo(segment),
				})
			}
			continue
		}
		if isGithubURL(segment) {
			actions = append(actions, ProviderAction{
				Action:   apiAction(commandLooksMutating(segment)),
				Resource: normalizeGithubRepo(segment),
			})
		}
	}
	return actions
}

func apiAction(mutating bool) string {
	if mutating {
		return "github.api.write"
	}
	return "github.api.read"
}

func classifyGhCommand(args []string, raw string, gitContext func() GitContext) ProviderAction {
	positional := ghPositionals(args)
	area := "api"
	if len(positional) > 0 {
		area = positional[0]
	}
	verb := ""
	if len(positional) > 1 {
		verb = positional[1]
	}
	resource := githubRepoFromGhArgs(args)
	if resource == "" && area == "api" && len(positional) > 1 {
		// A literal REST endpoint names the repository it targets; -R only
		// fills {owner}/{repo} placeholders.
		resource = githubRepoFromAPIEndpoint(positional[1])
	}
	if resource == "" && area == "repo" && len(positional) > 2 {
		// gh repo verbs take the target repository as a positional argument.
		resource = normalizeGithubRepo(positional[2])
	}
	if resource == "" {
		// Local extension over the cloud classifier: gh acts on the current
		// repository when -R/--repo is absent, and the endpoint knows its cwd
		// remotes, so resolve the policy anchor from them.
		resource = githubRepoFromGitContext(gitContext())
	}

	switch area {
	case "api":
		return ProviderAction{Action: apiAction(ghAPILooksMutating(args, raw)), Resource: resource}
	case "pr":
		return ProviderAction{Action: readWriteAction("github.pr", isReadVerb(verb)), Resource: resource}
	case "issue":
		return ProviderAction{Action: readWriteAction("github.issue", isReadVerb(verb)), Resource: resource}
	case "repo":
		return ProviderAction{Action: readWriteAction("github.repo", isReadVerb(verb)), Resource: resource}
	case "workflow":
		mutating := verb == "run" || verb == "enable" || verb == "disable"
		return ProviderAction{Action: apiAction(mutating), Resource: resource}
	}
	return ProviderAction{Action: apiAction(commandLooksMutating(raw)), Resource: resource}
}

func readWriteAction(prefix string, read bool) string {
	if read {
		return prefix + ".read"
	}
	return prefix + ".write"
}

func classifyGitCommand(args []string, raw string, gitContext func() GitContext) []ProviderAction {
	positionals := gitPositionals(args)
	if len(positionals) == 0 {
		return nil
	}
	verb := positionals[0]

	var context GitContext
	contextLoaded := false
	loadContext := func() GitContext {
		if !contextLoaded {
			context = gitContext()
			contextLoaded = true
		}
		return context
	}

	selectedRemote := selectedGitRemoteURL(verb, args, loadContext)
	if !isGithubURL(raw) && !isGithubURL(selectedRemote) {
		return nil
	}

	action := "github.repo.read"
	if isGitWriteVerb(verb) {
		action = "github.repo.write"
	}
	resource := normalizeGithubRepo(raw)
	if resource == "" {
		resource = normalizeGithubRepo(selectedRemote)
	}
	if resource == "" {
		resource = githubRepoFromGitContext(loadContext())
	}

	base := ProviderAction{Action: action, Resource: resource}
	branchOrRefs := gitBranchOrRefsFromArgs(verb, args)
	if len(branchOrRefs) > 0 {
		actions := make([]ProviderAction, 0, len(branchOrRefs))
		for _, branchOrRef := range branchOrRefs {
			withBranch := base
			withBranch.BranchOrRef = branchOrRef
			actions = append(actions, withBranch)
		}
		return actions
	}
	if fallback := gitBranchFallback(verb, args, loadContext); fallback != "" {
		base.BranchOrRef = fallback
	}
	return []ProviderAction{base}
}

func stringField(input map[string]any, key string) (string, bool) {
	value, ok := input[key].(string)
	return value, ok
}

var assignmentPrefixRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func commandInvocation(command string) (string, []string) {
	tokens := tokenize(command)
	index := 0
	for ; index < len(tokens); index++ {
		if !assignmentPrefixRE.MatchString(tokens[index]) {
			break
		}
	}
	if index >= len(tokens) {
		return "", nil
	}
	return tokens[index], tokens[index+1:]
}

var dashCFlagRE = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

func unwrapShellLauncher(command string, args []string) (string, bool) {
	switch command {
	case "bash", "sh", "zsh":
		for i, arg := range args {
			if dashCFlagRE.MatchString(arg) {
				if i+1 < len(args) && args[i+1] != "" {
					return args[i+1], true
				}
				return "", false
			}
		}
		return "", false
	case "sudo":
		payload := sudoPayloadArgs(args)
		if len(payload) == 0 {
			return "", false
		}
		quoted := make([]string, len(payload))
		for i, value := range payload {
			quoted[i] = shellToken(value)
		}
		return strings.Join(quoted, " "), true
	}
	return "", false
}

var sudoValueOptions = map[string]bool{
	"-u": true, "--user": true,
	"-g": true, "--group": true,
	"-h": true, "--host": true,
}

func sudoPayloadArgs(args []string) []string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return args[i+1:]
		}
		if sudoValueOptions[arg] {
			i++
			continue
		}
		if hasOptionValuePrefix(arg, sudoValueOptions) {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return args[i:]
	}
	return nil
}

func hasOptionValuePrefix(arg string, options map[string]bool) bool {
	for option := range options {
		if strings.HasPrefix(arg, option+"=") {
			return true
		}
	}
	return false
}

var unsafeShellTokenRE = regexp.MustCompile(`[\s'"\\]`)

func shellToken(value string) string {
	if !unsafeShellTokenRE.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func tokenize(command string) []string {
	var tokens []string
	var current strings.Builder
	var quote rune

	for _, char := range command {
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			continue
		}
		if char == '"' || char == '\'' {
			quote = char
			continue
		}
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(char)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// githubRepoFromAPIEndpoint extracts the repository slug from a gh api
// endpoint argument: "repos/<owner>/<repo>/..." or a full API URL. Endpoints
// with {owner}/{repo} placeholders resolve through -R or the cwd instead.
func githubRepoFromAPIEndpoint(endpoint string) string {
	if strings.Contains(endpoint, "{") {
		return ""
	}
	if isGithubURL(endpoint) {
		return normalizeGithubRepo(endpoint)
	}
	segments := strings.Split(strings.TrimPrefix(strings.Trim(endpoint, "/"), "repos/"), "/")
	if !strings.HasPrefix(strings.Trim(endpoint, "/"), "repos/") || len(segments) < 2 {
		return ""
	}
	return normalizeGithubRepo(segments[0] + "/" + segments[1])
}

func githubRepoFromGhArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-R" || arg == "--repo" {
			if i+1 < len(args) {
				return normalizeGithubRepo(args[i+1])
			}
			return ""
		}
		if strings.HasPrefix(arg, "--repo=") {
			return normalizeGithubRepo(strings.TrimPrefix(arg, "--repo="))
		}
	}
	return ""
}

var ghValueOptions = map[string]bool{
	"-R": true, "--repo": true, "--hostname": true, "--jq": true, "-q": true,
	"--template": true, "-t": true, "--paginate": true, "--cache": true, "--preview": true,
	"--limit": true, "--state": true, "--base": true, "--head": true,
	"--label": true, "--author": true, "--assignee": true, "--milestone": true,
	"--search": true, "--json": true, "--field": true, "-F": true,
	"--raw-field": true, "-f": true, "--input": true,
	"-X": true, "--method": true, "--request": true, "-H": true, "--header": true,
}

var gitValueOptions = map[string]bool{
	"-C": true, "-c": true, "--config": true, "--git-dir": true,
	"--work-tree": true, "--namespace": true, "--exec-path": true,
	"--super-prefix": true, "--repo": true, "-o": true, "--push-option": true,
	"--receive-pack": true, "--exec": true, "--recurse-submodules": true,
	"-b": true, "--branch": true,
}

func ghPositionals(args []string) []string {
	return positionalsSkippingOptionValues(args, ghValueOptions)
}

func gitPositionals(args []string) []string {
	return positionalsSkippingOptionValues(args, gitValueOptions)
}

func positionalsSkippingOptionValues(args []string, valueOptions map[string]bool) []string {
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if valueOptions[arg] {
			i++
			continue
		}
		if hasOptionValuePrefix(arg, valueOptions) {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		positionals = append(positionals, arg)
	}
	return positionals
}

func githubRepoFromGitContext(context GitContext) string {
	remotes := context.githubRemotes()
	if len(remotes) == 0 {
		return ""
	}
	return normalizeGithubRepo(remotes[0])
}

func gitBranchOrRefsFromArgs(verb string, args []string) []string {
	positionals := gitPositionals(args)
	if len(positionals) == 0 || positionals[0] != verb {
		return nil
	}
	switch verb {
	case "push":
		refspecStart := 2
		if gitRepoFromArgs(args) != "" {
			refspecStart = 1
		}
		if refspecStart >= len(positionals) {
			return nil
		}
		var refs []string
		for _, refspec := range positionals[refspecStart:] {
			if ref := normalizeGitPushRef(refspec); ref != "" {
				refs = append(refs, ref)
			}
		}
		return refs
	case "fetch", "pull":
		if len(positionals) > 2 {
			if ref := normalizeGitRef(positionals[2]); ref != "" {
				return []string{ref}
			}
		}
	}
	return nil
}

func gitBranchFallback(verb string, args []string, gitContext func() GitContext) string {
	if verb == "push" {
		for _, arg := range args {
			if arg == "--all" || arg == "--mirror" || arg == "--tags" {
				return ""
			}
		}
	}
	// clone targets a fresh checkout, not the branch the cwd happens to be
	// on; only an explicit -b/--branch pins it.
	if verb == "clone" {
		return gitFlagValue(args, "-b", "--branch")
	}
	return gitContext().Branch
}

func gitFlagValue(args []string, flags ...string) string {
	for i, arg := range args {
		for _, flag := range flags {
			if arg == flag && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(arg, flag+"=") {
				return strings.TrimPrefix(arg, flag+"=")
			}
		}
	}
	return ""
}

func selectedGitRemoteURL(verb string, args []string, gitContext func() GitContext) string {
	if repo := gitRepoFromArgs(args); repo != "" {
		return repo
	}
	positionals := gitPositionals(args)
	if len(positionals) == 0 || positionals[0] != verb {
		return ""
	}
	if len(positionals) < 2 {
		// push/fetch/pull without an explicit remote still hit the network —
		// they default to origin, so the policy evaluation must too.
		if verb == "push" || verb == "fetch" || verb == "pull" {
			return gitContext().RemoteByName["origin"]
		}
		return ""
	}
	remote := positionals[1]
	if normalizeGithubRepo(remote) != "" {
		return remote
	}
	return gitContext().RemoteByName[remote]
}

func gitRepoFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--repo" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(arg, "--repo=") {
			return strings.TrimPrefix(arg, "--repo=")
		}
	}
	return ""
}

func normalizeGitRef(value string) string {
	if value == "" {
		return ""
	}
	source := strings.SplitN(value, ":", 2)[0]
	return strings.TrimPrefix(source, "refs/heads/")
}

func normalizeGitPushRef(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 2 && parts[1] != "" {
		return normalizeGitRef(parts[1])
	}
	return normalizeGitRef(parts[0])
}

var (
	githubSSHRepoRE  = regexp.MustCompile(`(?i)^git@github\.com:([^/\s]+/[^/\s]+)$`)
	githubAPIRepoRE  = regexp.MustCompile(`(?i)api\.github\.com/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`)
	githubURLRepoRE  = regexp.MustCompile(`(?i)github\.com[:/]([^/\s]+/[^/\s?#]+)`)
	githubSlugRepoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	dotGitSuffixRE   = regexp.MustCompile(`(?i)\.git$`)
)

func normalizeGithubRepo(value string) string {
	trimmed := dotGitSuffixRE.ReplaceAllString(strings.TrimSpace(value), "")
	if trimmed == "" {
		return ""
	}
	if match := githubSSHRepoRE.FindStringSubmatch(trimmed); match != nil {
		return match[1]
	}
	// REST API URLs nest the slug under /repos/; the generic URL pattern
	// would capture "repos/<owner>" instead. Non-repos API paths (orgs,
	// search, ...) carry no repository.
	if match := githubAPIRepoRE.FindStringSubmatch(trimmed); match != nil {
		return dotGitSuffixRE.ReplaceAllString(match[1], "")
	}
	if strings.Contains(strings.ToLower(trimmed), "api.github.com") {
		return ""
	}
	if match := githubURLRepoRE.FindStringSubmatch(trimmed); match != nil {
		return dotGitSuffixRE.ReplaceAllString(match[1], "")
	}
	if githubSlugRepoRE.MatchString(trimmed) {
		return trimmed
	}
	return ""
}

var commandSegmentSplitRE = regexp.MustCompile(`\s*(?:&&|\|\||;|\|)\s*`)

func splitCommandSegments(command string) []string {
	var segments []string
	for _, segment := range commandSegmentSplitRE.Split(command, -1) {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	return segments
}

func isGithubURL(value string) bool {
	return githubHostRE.MatchString(value)
}

func isReadVerb(verb string) bool {
	switch verb {
	case "", "view", "list", "status", "diff", "checks", "clone":
		return true
	}
	return false
}

func isGitWriteVerb(verb string) bool {
	switch verb {
	case "push", "commit", "tag":
		return true
	}
	return false
}

var (
	mutatingDataFlagRE   = regexp.MustCompile(`(?i)\s(-d|--data|--data-raw|--data-binary|--data-urlencode|--json|--form)(=|\s)`)
	mutatingMethodRE     = regexp.MustCompile(`(?i)(^|\s)(-X|--method|--request)(=|\s+)?(POST|PUT|PATCH|DELETE)\b`)
	mutatingURLMethodRE  = regexp.MustCompile(`(?i)\b(POST|PUT|PATCH|DELETE)\s+https?://(api\.)?github\.com[/:]`)
	mutatingHTTPCmdRE    = regexp.MustCompile(`(?i)\b(http|https)\s+(POST|PUT|PATCH|DELETE)\b`)
	explicitMethodFlagRE = regexp.MustCompile(`(?i)(^|\s)(-X|--method|--request)(=|\s+)?(GET|HEAD)\b`)
)

func commandLooksMutating(command string) bool {
	return mutatingDataFlagRE.MatchString(command) ||
		mutatingMethodRE.MatchString(command) ||
		mutatingURLMethodRE.MatchString(command) ||
		mutatingHTTPCmdRE.MatchString(command)
}

var ghAPIBodyFlags = []string{"-f", "-F", "--field", "--raw-field", "--input"}

func ghAPILooksMutating(args []string, raw string) bool {
	if commandLooksMutating(raw) {
		return true
	}
	for _, arg := range args {
		for _, flag := range ghAPIBodyFlags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	// A method override we cannot prove to be GET/HEAD defaults to write:
	// unprovable gh api calls are treated as mutating.
	if hasMethodFlag(args) && !explicitMethodFlagRE.MatchString(raw) && !mutatingMethodRE.MatchString(raw) {
		return true
	}
	return false
}

func hasMethodFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-X" || arg == "--method" || arg == "--request" ||
			strings.HasPrefix(arg, "-X=") || strings.HasPrefix(arg, "--method=") || strings.HasPrefix(arg, "--request=") {
			return true
		}
	}
	return false
}
