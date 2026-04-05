# Kontext CLI

Governed agent sessions for Claude Code, Cursor, and other AI agents. One command to run any agent with scoped credentials and policy enforcement.

## How it works

```bash
kontext start --agent claude
```

1. **Authenticates** — loads your identity from the system keyring (set up via `kontext login`)
2. **Creates a session** — registers with the Kontext backend, visible in the dashboard
3. **Resolves credentials** — reads `.env.kontext`, exchanges placeholders for short-lived tokens
4. **Launches the agent** — spawns Claude Code with credentials injected as env vars + governance hooks
5. **Captures every action** — PreToolUse, PostToolUse, and UserPromptSubmit events streamed to the backend
6. **Tears down cleanly** — session disconnected, credentials expired, temp files removed

Credentials are ephemeral — scoped to the session, gone when it ends.

## Install

```bash
brew install kontext-dev/tap/kontext
```

Or build from source:

```bash
go build -o bin/kontext ./cmd/kontext
```

## Usage

### First-time setup

```bash
kontext start --agent claude
```

On first run, the CLI handles everything interactively:
- No session? Opens browser for OIDC login, stores refresh token in system keyring
- No `.env.kontext`? Prompts for which providers the project needs, writes the file
- Provider not connected? Opens browser to the Kontext hosted connect flow

### Declare credentials

The `.env.kontext` file declares what credentials the project needs:

```
GITHUB_TOKEN={{kontext:github}}
STRIPE_KEY={{kontext:stripe}}
DATABASE_URL={{kontext:postgres/prod-readonly}}
```

Commit this to your repo — the team shares it.

### Supported agents

| Agent | Flag | Status |
|---|---|---|
| Claude Code | `--agent claude` | Active |
| Cursor | `--agent cursor` | Planned |
| Codex | `--agent codex` | Planned |

## Architecture

```
kontext start --agent claude
  │
  ├── Auth: OIDC refresh token from keyring
  ├── ConnectRPC: CreateSession → session in dashboard
  ├── Sidecar: Unix socket server (kontext.sock)
  │     ├── Heartbeat loop (30s)
  │     └── Async event ingestion via ConnectRPC
  ├── Hooks: settings.json → Claude Code --settings
  ├── Agent: spawn claude with injected env
  │     │
  │     ├── [PreToolUse]        → kontext hook → sidecar → ingest
  │     ├── [PostToolUse]       → kontext hook → sidecar → ingest
  │     └── [UserPromptSubmit]  → kontext hook → sidecar → ingest
  │
  └── On exit: EndSession → cleanup
```

### Hook flow (per tool call)

```
Claude Code fires PreToolUse
  → spawns: kontext hook --agent claude
  → hook reads stdin JSON (tool_name, tool_input)
  → hook connects to sidecar via KONTEXT_SOCKET (Unix socket)
  → sidecar returns allow/deny immediately
  → sidecar ingests event to backend asynchronously
  → hook writes decision JSON to stdout, exits
  → ~5ms total (Go binary, no runtime startup)
```

## Telemetry Strategy

The CLI separates **governance telemetry** from **developer observability**. These are distinct concerns with different backends and data models.

### Governance telemetry (built-in)

Session lifecycle and tool call events flow to the Kontext backend. This powers the dashboard — sessions, traces, audit trail.

| Event | Source | When |
|---|---|---|
| `session.begin` | CLI lifecycle | Agent launched |
| `session.end` | CLI lifecycle | Agent exited |
| `hook.pre_tool_call` | PreToolUse hook | Before every tool execution |
| `hook.post_tool_call` | PostToolUse hook | After every tool execution |
| `hook.user_prompt` | UserPromptSubmit hook | User submits a prompt |

Events are ingested to the `mcp_events` table via `POST /api/v1/mcp-events`. Each session gets a `traceId` for grouping events in the traces view.

**What governance telemetry captures:**
- What the agent tried to do (tool name + input)
- What happened (tool response)
- Whether it was allowed (policy decision)
- Who did it (session → user → org attribution)
- When (timestamps, duration)

**What governance telemetry does NOT capture:**
- LLM reasoning or thinking
- Token usage or cost
- Model parameters
- Conversation history
- Response quality

### Developer observability (external, future)

LLM-level observability — generation details, token costs, reasoning traces, conversation history — is a separate concern. It is not part of the governance pipeline.

For this, the CLI will optionally export OpenTelemetry spans to an external backend:
- **Langfuse** — open-source, has a native Claude Code integration, self-hostable
- **Dash0** — OTEL-native SaaS, cheap ($0.60/M spans), AI/agent-aware

This is additive — the governance pipeline works independently. OTEL export is planned but not yet implemented.

## Protocol

Service definitions: [`proto/kontext/agent/v1/agent.proto`](proto/kontext/agent/v1/agent.proto)

The CLI communicates with the Kontext backend exclusively via ConnectRPC using the generated stubs. Requires the server-side `AgentService` endpoint ([kontext-dev/kontext#408](https://github.com/kontext-dev/kontext/issues/408)).

### Sidecar wire protocol

Hook handlers communicate with the sidecar over a Unix socket using length-prefixed JSON (4-byte big-endian uint32 + JSON payload):

- `EvaluateRequest` — hook → sidecar: agent, hook_event, tool_name, tool_input, tool_response
- `EvaluateResult` — sidecar → hook: allowed (bool), reason (string)

## Development

```bash
# Build
go build -o bin/kontext ./cmd/kontext

# Generate protobuf (requires buf + plugins)
buf generate

# Test
go test ./...

# Link for local use
ln -sf $(pwd)/bin/kontext ~/.local/bin/kontext
```

## License

MIT
