<div align="center">

<img src="assets/banner-cli.svg" alt="Kontext CLI banner" width="100%" />

<p><strong>Store Credentials. Inject At Runtime. Agents Never Store The Keys.</strong></p>

<p>
  <a href="https://kontext.security">Website</a>
  ·
  <a href="https://docs.kontext.security/getting-started/welcome">Documentation</a>
  ·
  <a href="https://app.kontext.security">Dashboard</a>
  ·
  <a href="https://discord.gg/gw9UpFUhyY">Discord</a>
</p>

<p>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-152822?labelColor=0d1714"></a>
  <a href="https://github.com/kontext-security/kontext-cli/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/kontext-security/kontext-cli?color=152822&labelColor=0d1714"></a>
  <img alt="Built with Go" src="https://img.shields.io/badge/Go-1.25-152822?labelColor=0d1714">
</p>

</div>

## What is Kontext CLI?

Kontext CLI is an open-source command-line tool that wraps AI coding agents with enterprise-grade identity, credential management, and governance — without changing how developers work.

**Why we built it:** AI coding agents need access to GitHub, Stripe, databases, and dozens of other services. Today, teams copy-paste long-lived API keys into `.env` files and hope for the best. Kontext replaces that with short-lived, scoped credentials that are injected at session start and gone when the session ends. Every tool call is logged. Every secret is accounted for.

**How it works:** On first run, kontext start authenticates you, bootstraps the shared Kontext CLI application for your org, creates a local .env.kontext file if needed, opens hosted connect for any missing preset providers, exchanges placeholders for short-lived tokens via RFC 8693 token exchange, and launches your agent with those credentials injected. When the session ends, credentials expire automatically.

## Quick Start

Install the CLI:

```bash
brew install kontext-security/tap/kontext
```

Run it from a project with Claude Code installed:

```bash
kontext start --agent claude
```

The first run opens your browser for login and provider connection. After that, `kontext start` resolves credentials, injects them into the agent process, and starts streaming governed tool events. The CLI session is stored in your system keyring and can be cleared with `kontext logout`.

Prefer a direct binary? Download the latest build from [GitHub Releases](https://github.com/kontext-security/kontext-cli/releases).

Need more detail while debugging startup? Run `kontext start --verbose` or set `KONTEXT_DEBUG=1` to print redacted diagnostics to stderr.

## Managed Credentials

The CLI creates `.env.kontext` locally on first run:

```dotenv
GITHUB_TOKEN={{kontext:github}}
LINEAR_API_KEY={{kontext:linear}}
```

Keep `.env.kontext` out of source control in repos that do not already ignore it. The CLI may append more preset provider placeholders later if your org attaches them to the shared Kontext CLI application. Literal values you add stay untouched. Providers connected after the agent has already started become available on the next `kontext start`.

## Providers and Traces

Provider setup and trace review live in the hosted dashboard at [app.kontext.security](https://app.kontext.security). Use the same account you used for `kontext login`.

**Add providers**

1. Open **Providers** in the dashboard.
2. Add a built-in provider, such as GitHub or Linear, or create a custom provider.
3. For built-in providers, configure allowed scopes and any provider-specific OAuth settings shown in the dashboard. For custom providers, choose end-user OAuth, end-user key, or organization key.
4. Open **Applications** → **kontext-cli** → **Providers** and attach the providers the CLI application can use.
5. Reference the provider handles in `.env.kontext`.

**Check traces**

1. Run `kontext start --agent claude`.
2. Ask Claude Code to perform a tool-using task.
3. Open **Traces** in the dashboard to inspect live hook events, tool calls, outcomes, user attribution, and session context.

## What You Get

| Capability | What it means |
| --- | --- |
| Ephemeral credentials | Short-lived tokens are injected only for the active agent session. |
| Managed env file | The CLI creates and updates `.env.kontext` with provider placeholders. |
| Hosted connect | Missing user providers open a browser flow instead of leaking keys locally. |
| Governed sessions | PreToolUse, PostToolUse, and UserPromptSubmit events stream to Kontext. |
| Native runtime | A small Go binary, no local daemon, no Docker, no Node or Python runtime. |

## Security

- OIDC browser login with refresh tokens stored in the system keyring.
- RFC 8693 token exchange for short-lived, provider-scoped runtime credentials.
- AES-256-GCM encryption at rest for provider credentials stored in Kontext.
- No long-lived provider keys are written to the project or agent config.

## Supported Agents

| Agent | Flag | Status |
| --- | --- | --- |
| Claude Code | `--agent claude` | Active |

Cursor and Codex support are planned, but they are not shipped in this repo yet.

## Architecture

```text
kontext start --agent claude
  │
  ├─ Auth: OIDC refresh token from system keyring
  ├─ ConnectRPC: CreateSession → governed session in dashboard
  ├─ BootstrapCli: sync managed provider entries into .env.kontext
  ├─ Token exchange: {{kontext:provider}} → short-lived credential
  ├─ Sidecar: Unix socket server + heartbeat loop
  ├─ Hooks: generated Claude Code settings.json
  │    │
  │    ├─ PreToolUse        → kontext hook → sidecar → ProcessHookEvent
  │    ├─ PostToolUse       → kontext hook → sidecar → ProcessHookEvent
  │    └─ UserPromptSubmit  → kontext hook → sidecar → ProcessHookEvent
  │
  └─ Exit: EndSession → credential expiry + temp file cleanup
```

The CLI communicates with the Kontext backend through ConnectRPC. Hook handlers talk to the sidecar over a Unix socket using length-prefixed JSON, keeping agent-specific hook parsing local to the CLI.

Kontext captures what the agent tried to do and what happened. It does not capture LLM reasoning, token usage, or conversation history.

## Development

```bash
go build -o bin/kontext ./cmd/kontext
go test ./...
go test -race ./...
go vet ./...
gofmt -w ./cmd ./internal
```

Generate protobuf code with `buf generate`.

Service definitions live in [kontext-security/proto `agent.proto`](https://github.com/kontext-security/proto/blob/main/proto/kontext/agent/v1/agent.proto).

## Community

- Read [SUPPORT.md](SUPPORT.md) for support channels.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a contribution.
- Kontext CLI is released under the [MIT License](LICENSE).
