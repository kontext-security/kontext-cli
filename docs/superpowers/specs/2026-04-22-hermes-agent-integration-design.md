# Hermes Agent Integration — Design

Status: Draft
Date: 2026-04-22
Branch: feat/hermesAgent

## 1. Goal & UX

`kontext start --agent hermes` launches the Nous Research Hermes agent with
short-lived provider credentials injected into its environment and routes tool
calls through a Kontext-managed MCP server so the existing governance and
trace pipeline (PreToolUse/PostToolUse allow-deny decisions plus dashboard
traces) works for Hermes. The user experience matches `--agent claude`: single
command, browser auth on first run, ephemeral credentials, governed session.

## 2. Background

Kontext CLI already supports Claude Code. That integration has two pillars:

1. **Credential injection** — `.env.kontext` placeholders like
   `GITHUB_TOKEN={{kontext:github}}` are exchanged via RFC 8693 at session
   start and injected into the agent process's environment.
2. **Governance via native hooks** — Kontext writes a session-scoped
   `settings.json` that registers Claude's `PreToolUse`, `PostToolUse`, and
   `UserPromptSubmit` hook commands pointing at `kontext hook --agent claude`.
   Those hook processes forward events to the Kontext sidecar over a Unix
   socket; the sidecar returns allow/deny and streams traces to the backend.

Hermes has no equivalent hook system. It does, however, support:

- `HERMES_HOME` env var to override the config directory.
- MCP servers registered in `$HERMES_HOME/config.yaml` under `mcp_servers:`.
- Stdio MCP transport (subprocess with command/args/env).
- Non-interactive launch via `hermes chat -q` / `-Q`.

The cleanest interception seam is therefore an MCP server run by Kontext that
Hermes connects to via stdio.

## 3. Architecture

```
kontext start --agent hermes
  |
  +- Auth + CreateSession + BootstrapCli               (shared)
  +- Resolve .env.kontext -> short-lived tokens        (shared)
  +- Build session HERMES_HOME/
  |    config.yaml  (user base + kontext MCP entry)
  |    .env         (resolved credentials KEY=VALUE)
  +- Sidecar: Unix socket server + heartbeat           (shared)
  +- Launch: HERMES_HOME=<session-dir> hermes          (fg, inherit stdio)
  |
  +- Hermes opens stdio MCP subprocess:
       `kontext mcp-serve --agent hermes --socket <sidecar-sock>`
           tools/list  -> governed tool surface
           tools/call  -> sidecar.ProcessHookEvent (PreToolUse)
                          -> execute call (uses resolved creds)
                          -> sidecar.ProcessHookEvent (PostToolUse)
                          -> return MCP result
```

## 4. Components

### 4.1 `internal/agent/hermes` (new)

Implements the existing `agent.Agent` interface for name `"hermes"`.

- `Name() string` — returns `"hermes"`.
- `DecodeHookInput([]byte) (*HookEvent, error)` — parses the JSON envelope
  that `kontext mcp-serve` forwards to the sidecar on each MCP `tools/call`.
- `EncodeAllow(*HookEvent, reason) ([]byte, error)` — returns a marker used
  by `mcp-serve` to proceed with the call.
- `EncodeDeny(*HookEvent, reason) ([]byte, error)` — returns a marker used
  by `mcp-serve` to abort and return an MCP error with the deny reason.

Registered via `agent.Register` in `init()`, parallel to the Claude adapter.

The hook envelope shape Kontext controls end-to-end (it originates in
`mcp-serve`, not in Hermes), so the adapter can use a Kontext-defined schema
rather than a vendor-specific one.

### 4.2 `internal/run/hermes_config.go` (new)

Session-dir builder:

- Create a per-session temp dir (e.g. `os.MkdirTemp("", "kontext-hermes-*")`).
- Copy/read the user's base `~/.hermes/config.yaml` if present; otherwise
  start from an empty map.
- Merge an `mcp_servers.kontext` stanza pointing at the Kontext binary:

  ```yaml
  mcp_servers:
    kontext:
      command: "/abs/path/to/kontext"
      args: ["mcp-serve", "--agent", "hermes", "--socket", "/tmp/.kontext.sock"]
      env:
        KONTEXT_SESSION: "<session-id>"
  ```

- Write the merged doc to `<session-dir>/config.yaml`.
- Write resolved credentials to `<session-dir>/.env` as `KEY=VALUE` lines
  (Hermes loads this automatically).

If the user already has an `mcp_servers.kontext` key, the session copy
overwrites it. The user's real `~/.hermes/config.yaml` is never mutated.

### 4.3 `cmd/kontext/mcp_serve.go` (new subcommand)

`kontext mcp-serve --agent <name> --socket <path>` implements an MCP server
over stdio. For MVP it exposes a single tool:

- `kontext.invoke(provider, action, params)` — performs an authenticated call
  to the named provider using the credentials already resolved into the
  process env. Response is returned as the MCP tool result.

Per-call flow:

1. Receive `tools/call` from Hermes.
2. Build a `HookEvent{HookEventName: "PreToolUse", ToolName, ToolInput,
   SessionID, CWD}`.
3. Send to sidecar over Unix socket using the existing length-prefixed JSON
   protocol (same path used by `kontext hook`).
4. On allow: execute the call; capture response.
5. On deny: return an MCP error with the deny reason; do not execute.
6. Send `HookEvent{HookEventName: "PostToolUse", ToolResponse, ...}` to the
   sidecar.
7. Return MCP result to Hermes.

The socket path is passed in by the parent `kontext start` process. The
`mcp-serve` process has no OIDC state of its own — it relies on the resolved
tokens already in its env.

### 4.4 `internal/run/run.go`

Add a `hermes` branch parallel to the existing `claude` branch:

- Pick config writer (`GenerateSettings` vs `BuildHermesHome`).
- Pick launch argv (`claude` vs `hermes`).
- Pass `HERMES_HOME=<session-dir>` in the child env.
- All other plumbing (auth, sidecar, credential resolution, EndSession,
  diagnostics) is shared.

## 5. Data flow for one tool call

1. User prompt -> Hermes LLM decides to call `kontext.invoke`.
2. Hermes uses the existing stdio pipe to `kontext mcp-serve`.
3. `mcp-serve` emits PreToolUse to sidecar -> backend.
4. Backend returns allow or deny.
5. On allow: `mcp-serve` executes the provider call using the env-injected
   token; captures response.
6. On deny: `mcp-serve` returns an MCP error; no execution.
7. `mcp-serve` emits PostToolUse with `ToolResponse` to sidecar -> backend.
8. MCP `tools/call` result returns to Hermes.

## 6. Credential injection

Identical to Claude:

- `.env.kontext` placeholders resolved at session start via RFC 8693.
- Resolved values written into `$HERMES_HOME/.env` so Hermes itself picks
  them up.
- The same values are also embedded in the `env:` block of the `kontext`
  `mcp_servers` entry in `config.yaml`, so when Hermes spawns `mcp-serve`
  as a stdio subprocess, `mcp-serve` has them available for authenticated
  calls on Hermes's behalf.

Kontext never stores long-lived provider keys on disk.

## 7. Session teardown

Reuses the existing `run` cleanup path:

- Call `EndSession` via ConnectRPC.
- Let short-lived tokens expire (no revoke needed).
- Delete the session `HERMES_HOME` temp dir.
- Stop the sidecar.
- `mcp-serve` exits when its stdin closes (Hermes shuts it down as part of
  MCP teardown).

## 8. Error handling

| Condition | Behavior |
| --- | --- |
| `hermes` binary not on PATH | Fail before `CreateSession` with a clear error. |
| User has no `~/.hermes/config.yaml` | Start from an empty config; only Kontext entries are present. |
| User already has `mcp_servers.kontext` | Session copy overwrites; user's real config untouched. |
| Sidecar unreachable from `mcp-serve` | Deny by default with a diagnostic reason. |
| MCP stdio pipe drops | `mcp-serve` exits; Hermes surfaces MCP disconnect; tool calls fail closed; session continues. |
| Credential resolution partial failure | Same behavior as Claude path — launch warnings, entry omitted from `.env`. |

## 9. Testing

**Unit**

- `internal/agent/hermes`: `DecodeHookInput`, `EncodeAllow`, `EncodeDeny`
  against fixture payloads.
- `internal/run`: config merger with/without existing user config;
  deterministic `.env` writer (sorted keys, quoted values).

**Integration**

- Spin up `kontext mcp-serve` against a fake sidecar over a Unix socket.
- Drive it with an MCP client harness that issues `tools/list` and
  `tools/call`.
- Assert PreToolUse/PostToolUse events are emitted with the expected
  shape; assert deny returns an MCP error.

**End-to-end (manual, documented)**

- `kontext start --agent hermes` with a dummy provider.
- Trace appears in the dashboard.
- `.env.kontext` placeholders resolve; user's `~/.hermes` is unchanged.

## 10. Scope cuts (not in MVP)

- Proxying arbitrary user-configured MCP servers through Kontext
  (middleware mode). MVP exposes only the Kontext tool surface.
- Governing tools Hermes calls natively (its shell, filesystem, skills) —
  explicit blind spot until Hermes gains a hook API upstream.
- Custom per-tool policy UI for Hermes-specific tools in the dashboard.
- `UserPromptSubmit`-equivalent events for Hermes (no natural seam via
  MCP).

## 11. Open questions

None blocking for MVP. Future work:

- Should Kontext also act as an MCP middleware in front of user-configured
  MCP servers? (Would require intercepting Hermes's MCP client config and
  rewriting each server entry to route through Kontext.)
- Upstream PR to Hermes for a hook API comparable to Claude Code's
  `PreToolUse`/`PostToolUse`/`UserPromptSubmit`.
