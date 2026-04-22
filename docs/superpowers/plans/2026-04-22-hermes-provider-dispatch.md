# Hermes Provider Dispatch Implementation Plan

> Follow-up to `2026-04-22-hermes-agent-integration.md`. This plan makes `kontext.invoke` actually do things, starting with GitHub. Required because Hermes's terminal sandbox strips provider env vars from subprocess tool calls, so env-injection alone is insufficient.

**Goal:** `mcp-serve` becomes a self-sufficient provider gateway. Hermes calls typed per-provider tools (e.g. `kontext.github.list_repos`); `mcp-serve` performs the HTTP call against the provider API using credentials already in its process env; result flows back to Hermes with PreToolUse/PostToolUse governance on each call.

**Architecture:** Introduce `internal/mcpserve/providers` — a small registry of providers, each declaring a set of actions with JSON-schema parameters. Each action is registered as a dedicated MCP tool (`kontext.<provider>.<action>`). The tool handler dispatches to the provider's action function, which runs Pre-hook → HTTP call → Post-hook.

**Tech Stack:** Go 1.25, existing sidecar bridge, `net/http`, `httptest` for unit tests.

---

## File Structure

- Modify: `internal/run/hermes_config.go` — inline resolved tokens in yaml `env:` block.
- Modify: `internal/mcpserve/server.go` — replace `kontext.invoke` stub with provider-registry-driven tool registration.
- Create: `internal/mcpserve/providers/providers.go` — registry + `Provider` / `Action` types.
- Create: `internal/mcpserve/providers/github.go` — GitHub provider with `get_user`, `list_repos`, `list_issues`, `create_issue`.
- Create: `internal/mcpserve/providers/providers_test.go` + `github_test.go` — unit tests.

---

## Task 1: Inline resolved credentials in yaml env

**Files:**
- Modify: `internal/run/hermes_config.go` — change `writeHermesConfig` signature + callers.
- Modify: `internal/run/hermes_config_test.go` — update test expectations.

Change `writeHermesConfig` to take `passthrough map[string]string` (env name → resolved value) instead of `passthroughEnv []string`. Inline the real values in the yaml. Update `BuildHermesHome` to pass a map built from `resolved`.

- [ ] **Step 1:** Read current `writeHermesConfig` + tests; update tests to expect inlined real values; confirm tests fail.
- [ ] **Step 2:** Change `writeHermesConfig(sessionDir, basePath, kontextBin, socketPath, sessionID string, passthrough map[string]string)`; inline `envMap[name] = value` for each entry.
- [ ] **Step 3:** Update `BuildHermesHome` to build `map[string]string{envVar: value}` from `resolved` and pass it.
- [ ] **Step 4:** Run `go test ./internal/run/...` — all pass.
- [ ] **Step 5:** Commit: `fix(hermes): inline resolved creds in mcp-serve yaml env`.

---

## Task 2: Provider registry scaffolding

**Files:**
- Create: `internal/mcpserve/providers/providers.go`
- Create: `internal/mcpserve/providers/providers_test.go`

Define types:

```go
package providers

import "context"

type Action struct {
	Name        string
	Description string
	Params      []Param
	Handler     Handler
}

type Param struct {
	Name        string
	Type        string // "string", "number", "boolean", "object"
	Description string
	Required    bool
}

type Handler func(ctx context.Context, args map[string]any) (any, error)

type Provider struct {
	Name    string
	Actions []Action
}

type Registry struct{ providers map[string]*Provider }

func NewRegistry() *Registry { return &Registry{providers: map[string]*Provider{}} }
func (r *Registry) Register(p *Provider) { r.providers[p.Name] = p }
func (r *Registry) All() []*Provider { /* ... */ }
```

- [ ] **Step 1:** Write a registry test (Register + All).
- [ ] **Step 2:** Run to confirm failure.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run tests; commit.

---

## Task 3: GitHub provider

**Files:**
- Create: `internal/mcpserve/providers/github.go`
- Create: `internal/mcpserve/providers/github_test.go`

Four actions using `GITHUB_TOKEN` from env, hitting `api.github.com`:
- `get_user` (no params) → `GET /user`.
- `list_repos` (optional: `visibility`, `per_page`) → `GET /user/repos`.
- `list_issues` (required: `owner`, `repo`; optional: `state`) → `GET /repos/{owner}/{repo}/issues`.
- `create_issue` (required: `owner`, `repo`, `title`; optional: `body`) → `POST /repos/{owner}/{repo}/issues`.

Factor an HTTP helper that:
- Reads `GITHUB_TOKEN` env (`os.Getenv`); returns a typed "credential missing" error if empty.
- Allows a base URL override via unexported package var for tests (default `https://api.github.com`).
- Sets `Accept: application/vnd.github+json`, `Authorization: Bearer <token>`, `X-GitHub-Api-Version: 2022-11-28`.
- Decodes JSON response; surfaces non-2xx as an error with body preview.

- [ ] **Step 1:** Write `github_test.go` with an `httptest.Server`, override base URL, test each of the four actions (success + one token-missing case).
- [ ] **Step 2:** Run to confirm failure.
- [ ] **Step 3:** Implement `github.go`; add an `init()` that registers itself into a package-level default registry (or have the caller register it).
- [ ] **Step 4:** Run tests; commit.

---

## Task 4: Wire registry into mcp-serve

**Files:**
- Modify: `internal/mcpserve/server.go`

Replace the single `kontext.invoke` registration with a loop that iterates the provider registry and registers one MCP tool per action, named `kontext.<provider>.<action>`.

The handler for each action:
1. Builds a `HookEvent` with `ToolName = "kontext.<provider>.<action>"`, `ToolInput = args`.
2. Sends PreToolUse to sidecar via existing `handler.sendHook`.
3. On deny, returns MCP error with reason.
4. On allow, calls the action's handler function.
5. Sends PostToolUse with response.
6. Returns the JSON-encoded response as MCP text result.

Reuse the existing `handler`, `sendHook`. Remove the old `handler.invoke` stub (or keep a thin wrapper that delegates to registry for name "kontext.invoke").

- [ ] **Step 1:** Write a test that confirms registry-driven tool registration by invoking one tool through the handler against a fake sidecar (allow path), checking the GitHub action was called and result passed through.
- [ ] **Step 2:** Run to confirm failure.
- [ ] **Step 3:** Refactor `server.go`: replace `invoke` with `dispatch(ctx, toolName, handlerFn, args)`; in `Run`, iterate registry and register each action as a tool.
- [ ] **Step 4:** Run `go test ./internal/mcpserve/...` — all pass (existing Allow/Deny tests + new registry test).
- [ ] **Step 5:** Commit.

---

## Task 5: Smoke test update

**Files:** none (manual verification)

- [ ] Build: `go build -o bin/kontext ./cmd/kontext`.
- [ ] Start: `./bin/kontext start --agent hermes`.
- [ ] In Hermes: "list the available kontext tools" — should see `kontext.github.list_repos`, `kontext.github.get_user`, etc.
- [ ] Ask Hermes to "use kontext.github.get_user" — returns the GitHub user tied to your session token.
- [ ] Dashboard traces show PreToolUse + PostToolUse for that call.
