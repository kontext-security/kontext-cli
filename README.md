<img src="assets/kontext-banner-cli.svg" alt="Kontext CLI banner" width="100%" />

<div align="center">

<p>
  <a href="https://kontext.security">Website</a>
  |
  <a href="https://docs.kontext.security/getting-started/welcome">Documentation</a>
  |
  <a href="https://app.kontext.security">Dashboard</a>
  |
  <a href="https://discord.gg/gw9UpFUhyY">Discord</a>
</p>

<p>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-152822?labelColor=0d1714"></a>
  <a href="https://github.com/kontext-security/kontext-cli/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/kontext-security/kontext-cli?color=152822&labelColor=0d1714"></a>
  <img alt="Built with Go" src="https://img.shields.io/badge/Go-1.25-152822?labelColor=0d1714">
</p>

</div>

Kontext is an authorization platform for AI agents. It helps teams control what agents can access and do with scoped credentials, policy enforcement, approvals, and audit trails. Kontext can run local-first for developer agents and extend to managed or self-hosted deployments for security-sensitive environments.

## 🚀 Quickstart

```bash
brew install kontext-security/tap/kontext
```

The Homebrew package also installs `llama.cpp`, which provides the `llama-server` runtime used by the local LLM judge. On first use, Kontext manages the default GGUF judge model automatically: if the model is not already cached locally, it downloads it into the Kontext model cache before starting `llama-server` on loopback.

## Start a local protected session

```bash
kontext start
```

This starts the currently supported adapter, Claude Code, with a local Kontext runtime. No hosted login is required.

By default, Kontext runs in observe mode: the agent keeps running, while Kontext records `would allow` and `would deny` decisions in the local dashboard. The dashboard is served on loopback, with the URL printed at startup.

To block supported risky pre-tool actions, start in enforce mode:

```bash
KONTEXT_MODE=enforce kontext start
```

## Core features

Kontext balances security and utility for AI agents: low-risk actions keep moving, and unsafe actions can be blocked before they execute.

- **Audit trails:** Record who instructed which agent to do what, what the agent accessed, which tools it called, what policy decisions were made, and what happened next. Build a chain of custody for security review, incident investigation, and compliance evidence.
- **Deterministic policy:** Apply `allow` and `deny` rules to agent actions at runtime, before they execute. Use hard policies for known boundaries such as destructive commands, production resources, sensitive files, data exports, and credential access.
- **Probabilistic risk detection:** Route actions that deterministic policy allows through a local judge for an additional allow/deny decision without sending tool context to hosted services.
- **Credential injection:** Inject scoped OAuth credentials at runtime using RFC 8693-compliant OAuth 2.0 Token Exchange, so agents can access approved tools without users pasting secrets into chat, config files, or project environments. Credentials can be short-lived, least-privilege, and bound to the current user, session, or workflow.

The local decision path is:

```text
Agent tool call
  -> Kontext hook
  -> local runtime socket
  -> action classification
  -> deterministic policy
  -> probabilistic risk score
  -> allow / deny
  -> local dashboard
```

## Connect to your Kontext workspace (self-serve)

Stream Claude Code activity from this Mac into your team's hosted Kontext
dashboard — no MDM required. Generate an install token on your workspace's
Deployments page, then:

```bash
kontext setup
```

Setup validates the token, stores it in your login keychain, installs the
Claude Code hooks, and starts a background agent. Sessions appear in your
dashboard seconds after your next Claude Code activity. Re-running `kontext
setup` rotates the token; `kontext setup --uninstall` removes everything it
installed. macOS only.

## Managed sessions

Use managed sessions when you want hosted identity, short-lived provider credentials, and shared traces on top of the local safety path:

```bash
kontext start --managed
```

Managed sessions keep provider credentials out of agent config and project files. Kontext creates `.env.kontext` with provider placeholders:

```dotenv
GITHUB_TOKEN={{kontext:github}}
LINEAR_API_KEY={{kontext:linear}}
```

At runtime, Kontext exchanges those placeholders for short-lived scoped credentials for the active agent session using RFC 8693-compliant OAuth 2.0 Token Exchange. Literal values you add stay untouched.

For enterprise identity, audit retention, organization controls, deployment planning, custom usage volume, and onboarding for security and platform teams, contact [michel@kontext.security](mailto:michel@kontext.security) or [book here](https://calendar.superhuman.com/book/11W5Y8b5JsB8dOzQbd/YECs9).

## Security defaults

| Default | Behavior |
| --- | --- |
| Local evaluation | Default `kontext start` does not require hosted login or trace upload. |
| Observe mode | Decisions are recorded as `would allow` or `would deny` without blocking the agent. |
| Loopback dashboard | The local dashboard binds to loopback by default. |
| Redacted storage | Tool events and decisions are stored locally with redaction. |
| Managed local judge | Homebrew installs `llama-server` via `llama.cpp`; Kontext downloads and caches the default GGUF judge model when needed. |
| No reasoning capture | Kontext captures tool events and outcomes, not LLM reasoning, token usage, or full conversation history. |

## Agent support

| Agent | Status | Start command | Support level |
| --- | --- | --- | --- |
| Claude Code | Active | `kontext start` or `kontext start --agent claude` | Local observe/enforce, dashboard diagnostics, managed sessions. |
| Goose | Planned | Coming soon | Adapter not shipped yet. |
| Codex | Planned | Coming soon | Adapter not shipped yet. |
| Cursor | Planned | Coming soon | Adapter not shipped yet. |

Additional agents can be added through adapters that send compatible tool events into the local runtime.

## Architecture

```text
kontext start
  |
  |-- Agent hook adapter (Claude Code today)
  |     |-- PreToolUse  -> kontext hook --agent claude --mode observe --socket /tmp/kontext/.../kontext.sock
  |     |-- PostToolUse -> kontext hook --agent claude --mode observe --socket /tmp/kontext/.../kontext.sock
  |
  |-- Local runtime: Unix socket service + RuntimeCore
  |-- Local dashboard: 127.0.0.1:4765
  |-- Deterministic policy: curated rule categories + active profile
  |-- Probabilistic risk: localhost allow/deny decision after deterministic allow
  |-- Store: local SQLite with redacted events and decision metadata
```

## Development

```bash
go build -o bin/kontext ./cmd/kontext
go test ./...
go test -race ./...
go vet ./...
pnpm install --frozen-lockfile
pnpm build
```

Generate protobuf code with:

```bash
buf generate
```

Service definitions live in [kontext-security/proto `agent.proto`](https://github.com/kontext-security/proto/blob/main/proto/kontext/agent/v1/agent.proto).

## Community

- Read [SUPPORT.md](SUPPORT.md) for support channels.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a contribution.
- Kontext CLI is released under the [MIT License](LICENSE).
