# Kontext CLI

The identity layer for AI agents.
One command. Scoped credentials. Full audit trail. Agents never touch the keys.

[Website](https://kontext.dev) · [Docs](https://docs.kontext.dev) · [Discord](https://discord.gg/kontext)

## What is Kontext CLI?

Kontext CLI is an open-source command-line tool that wraps your AI coding agents (Claude Code, Cursor, Codex) with enterprise-grade identity, credential management, and governance — without changing how you use them.

**Why we built it:** AI coding agents need access to GitHub, Stripe, databases, and dozens of other services. Today, teams copy-paste long-lived API keys into `.env` files and hope for the best. Kontext replaces that with short-lived, scoped credentials that are injected at session start and gone when the session ends. Every tool call is logged. Every secret is accounted for.

**How it works:** You declare what credentials your project needs in a single `.env.kontext` file. When you run `kontext start`, the CLI authenticates you, exchanges placeholders for short-lived tokens via RFC 8693 token exchange, launches your agent with those credentials injected, and streams every tool call to the Kontext dashboard for audit and governance. When the session ends, credentials expire automatically.

## Quick Start

```bash
brew install kontext-dev/tap/kontext
```

Then, from any project directory:

```bash
kontext start --agent claude
```

That's it. On first run, the CLI handles everything interactively — login, provider connections, credential resolution.

## How it Works

```bash
kontext start --agent claude
```

1. **Authenticates** — opens browser for OIDC login, stores refresh token in system keyring
2. **Creates a session** — registers with the Kontext backend, visible in the dashboard
3. **Resolves credentials** — reads `.env.kontext`, exchanges placeholders for short-lived tokens
4. **Launches the agent** — spawns Claude Code with credentials injected as env vars + governance hooks
5. **Captures every action** — PreToolUse, PostToolUse, and UserPromptSubmit events streamed to the backend
6. **Tears down cleanly** — session ended, credentials expired, temp files removed

## Features

- **One command to launch any agent:** `kontext start --agent claude` — no config files, no Docker, no setup scripts
- **Ephemeral credentials:** short-lived tokens scoped to the session, automatically expired on exit. No more long-lived API keys in `.env` files
- **Declarative credential templates:** commit `.env.kontext` to your repo, and every developer on the team gets the same credential setup without sharing secrets
- **Full audit trail:** every tool call, every file edit, every command — streamed to the dashboard with user, session, and org attribution
- **Policy enforcement:** PreToolUse hooks evaluate allow/deny before the agent acts, with ~5ms overhead (native Go binary, no runtime startup)
- **Secure by default:** OIDC authentication, system keyring storage, RFC 8693 token exchange, AES-256-GCM encryption at rest
- **Agent-agnostic:** works with Claude Code today, with Cursor and Codex support coming

## Declare Credentials

The `.env.kontext` file declares what credentials the project needs:

```
GITHUB_TOKEN={{kontext:github}}
STRIPE_KEY={{kontext:stripe}}
DATABASE_URL={{kontext:postgres/prod-readonly}}
```

Commit this to your repo — the whole team shares the same template. Secrets stay in Kontext, never in source control.

## Supported Agents

| Agent       | Flag             | Status  |
| ----------- | ---------------- | ------- |
| Claude Code | `--agent claude` | Active  |
| Cursor      | `--agent cursor` | Planned |
| Codex       | `--agent codex`  | Planned |

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

**Go sidecar:** A lightweight sidecar process runs alongside the agent, communicating over a Unix socket. Hook handlers evaluate policy decisions in ~5ms and stream events asynchronously to the backend — zero impact on agent performance.

**Governance telemetry:** Session lifecycle and tool call events flow to the Kontext backend, powering the dashboard with sessions, traces, and full audit trail. The CLI captures what the agent tried to do, what happened, and whether it was allowed — but never captures LLM reasoning, token usage, or conversation history.

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

## Protocol

Service definitions: [`proto/kontext/agent/v1/agent.proto`](proto/kontext/agent/v1/agent.proto)

The CLI communicates with the Kontext backend exclusively via ConnectRPC. Hook handlers communicate with the sidecar over a Unix socket using length-prefixed JSON.

## License

MIT
