<div align="center">

<img src="assets/banner-cli.png" alt="Kontext CLI banner" width="auto" height="auto" style="margin-bottom: 20px;" />

# Kontext CLI

Identity, credentials, and governance for AI agents.

[Website](https://kontext.security) · [Documentation](https://kontext.security/docs) · [Discord](https://discord.gg/gw9UpFUhyY)

</div>

## What is Kontext CLI?

Kontext CLI is an open-source command-line tool that wraps AI coding agents with enterprise-grade identity, credential management, and governance — without changing how developers work.

**Why we built it:** AI coding agents need access to GitHub, Stripe, databases, and dozens of other services. Today, teams copy-paste long-lived API keys into `.env` files and hope for the best. Kontext replaces that with short-lived, scoped credentials that are injected at session start and gone when the session ends. Every tool call is logged. Every secret is accounted for.

**How it works:** You declare what credentials your project needs in a single `.env.kontext` file. When you run `kontext start`, the CLI authenticates you, exchanges placeholders for short-lived tokens via RFC 8693 token exchange, launches your agent with those credentials injected, and streams every tool call to the Kontext dashboard for audit and governance. When the session ends, credentials expire automatically.

## Quick Start

```bash
brew install kontext-dev/tap/kontext
```

If you prefer a direct binary install, download the latest GitHub Release instead:

```bash
tmpdir="$(mktemp -d)" \
  && gh release download --repo kontext-dev/kontext-cli --pattern 'kontext_*_darwin_arm64.tar.gz' --dir "$tmpdir" \
  && archive="$(find "$tmpdir" -maxdepth 1 -name 'kontext_*_darwin_arm64.tar.gz' -print -quit)" \
  && tar -xzf "$archive" -C "$tmpdir" \
  && sudo install -m 0755 "$tmpdir/kontext" /usr/local/bin/kontext
```

Then, from any project directory with Claude Code installed:

```bash
kontext start --agent claude
```

That's it. On first run, the CLI handles everything interactively — login, provider connections, credential resolution.
Run `kontext logout` any time to clear the stored OIDC session from your system keyring.

## How it Works

```bash
kontext start --agent claude
```

1. **Authenticates** — opens browser for OIDC login, stores refresh token in system keyring, and lets you clear it later with `kontext logout`
2. **Creates a session** — registers with the Kontext backend, visible in the dashboard
3. **Resolves credentials** — reads `.env.kontext`, exchanges placeholders for short-lived tokens
4. **Launches the agent** — spawns Claude Code with credentials injected as env vars + governance hooks
5. **Captures hook events** — PreToolUse, PostToolUse, and UserPromptSubmit events streamed to the backend
6. **Tears down cleanly** — session ended, credentials expired, temp files removed

## Features

- **One command to launch Claude Code:** `kontext start --agent claude` — no config files, no Docker, no setup scripts
- **Ephemeral credentials:** short-lived tokens scoped to the session, automatically expired on exit. No more long-lived API keys in `.env` files
- **Declarative credential templates:** commit `.env.kontext` to your repo, and every developer on the team gets the same credential setup without sharing secrets
- **Governance telemetry:** Claude hook events are streamed to the backend with user, session, and org attribution
- **Secure by default:** OIDC authentication, system keyring storage, RFC 8693 token exchange, AES-256-GCM encryption at rest
- **Lean runtime:** native Go binary, no local daemon install, no Node/Python runtime required
- **Update notifications:** on `kontext start`, a background check queries the public GitHub releases API (cached for 24h, never blocks startup). Disable with `KONTEXT_NO_UPDATE_CHECK=1`

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

Cursor and Codex support are planned, but they are not shipped in this repo yet.

## Architecture

```
kontext start --agent claude
  │
  ├── Auth: OIDC refresh token from keyring
  ├── ConnectRPC: CreateSession → session in dashboard
  ├── Sidecar: Unix socket server (kontext.sock)
  │     └── Heartbeat loop (30s)
  ├── Hooks: settings.json → Claude Code --settings
  ├── Agent: spawn claude with injected env
  │     │
  │     ├── [PreToolUse]        → kontext hook → sidecar → backend
  │     ├── [PostToolUse]       → kontext hook → sidecar → backend
  │     └── [UserPromptSubmit]  → kontext hook → sidecar → backend
  │
  └── On exit: EndSession → cleanup
```

**Go sidecar:** A lightweight sidecar process runs alongside the agent and communicates over a Unix socket. Hook handlers send normalized events through the sidecar so the CLI can keep agent-specific logic out of the backend contract.

**Governance telemetry:** Session lifecycle and hook events flow to the Kontext backend, powering the dashboard with sessions, traces, and audit history. The CLI captures what the agent tried to do and what happened, but never captures LLM reasoning, token usage, or conversation history.

## Development

```bash
# Build
go build -o bin/kontext ./cmd/kontext

# Generate protobuf (requires buf + plugins)
buf generate

# Test
go test ./...
go test -race ./...
go vet ./...
gofmt -w ./cmd ./internal

# Link for local use
ln -sf $(pwd)/bin/kontext ~/.local/bin/kontext
```

## Protocol

Service definitions: [kontext-dev/proto `agent.proto`](https://github.com/kontext-dev/proto/blob/main/proto/kontext/agent/v1/agent.proto)

The CLI communicates with the Kontext backend exclusively via ConnectRPC. Hook handlers communicate with the sidecar over a Unix socket using length-prefixed JSON.

## License

MIT

## Support

See [SUPPORT.md](SUPPORT.md) for the right support channel.
