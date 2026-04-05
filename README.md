# Kontext CLI

Governed agent sessions for Claude Code. Wraps Claude Code with [Kontext](https://kontext.security) hooks for telemetry and policy enforcement.

## How it works

`kontext start` launches Claude Code with governance hooks injected via Claude Code's native hook system. Every tool call (Bash, Edit, Write, MCP) is reported to the Kontext API as a telemetry event. The developer interacts with Claude Code normally — the hooks run transparently in the background.

```
kontext start
  ├── Authenticate (service account credentials)
  ├── Create agent session
  ├── Generate hooks-only settings.json
  ├── Spawn Claude Code with hooks
  │     ├── PreToolUse  → POST /agent-sessions/:id/evaluate-tool (telemetry)
  │     └── PostToolUse → POST /agent-sessions/:id/evaluate-tool (async telemetry)
  └── On exit: disconnect session, clean up
```

## Install

```bash
npm install -g @kontext-dev/cli
```

Or link locally from source:

```bash
pnpm install && pnpm build
ln -sf "$(pwd)/dist/bin.mjs" ~/.local/bin/kontext
```

## Usage

### Quick start

```bash
export KONTEXT_CLIENT_ID=<your-client-id>
export KONTEXT_CLIENT_SECRET=<your-client-secret>
export KONTEXT_API_URL=https://api.kontext.security

kontext start
```

Claude Code launches with Kontext hooks active. Tool calls are logged to your Kontext dashboard.

### Commands

#### `kontext start`

Launch Claude Code with governance hooks.

```bash
kontext start                          # basic
kontext start --user sara@acme.com     # explicit developer identity
kontext start --api-url https://...    # override API URL
kontext start -- --model sonnet        # pass args through to Claude Code
```

**Environment variables:**

| Variable | Required | Description |
|---|---|---|
| `KONTEXT_CLIENT_ID` | Yes | Application or service account client ID |
| `KONTEXT_CLIENT_SECRET` | Yes | Application or service account client secret |
| `KONTEXT_API_URL` | No | Kontext API base URL (default: `https://api.kontext.security`) |

#### `kontext login`

Authenticate with Kontext via browser (PKCE flow).

```bash
kontext login
kontext login --api-url https://api.staging.kontext.security
```

#### `kontext hook`

Internal hook handlers invoked by Claude Code. Not meant to be called directly.

```bash
kontext hook pre-tool-use    # PreToolUse hook (reads stdin, writes stdout)
kontext hook post-tool-use   # PostToolUse hook (async, reads stdin)
```

## Architecture

The CLI generates a hooks-only `settings.json` that Claude Code loads alongside existing user/project settings. No interference with your permissions, tool allowlists, or MCP configs.

**PreToolUse hooks** fire on `Bash|Edit|Write|mcp__.*` tool calls. They call the Kontext API to log the event. In the current MVP, all calls are allowed (telemetry-only). Policy enforcement (blocking via exit code 2) is planned.

**PostToolUse hooks** fire on all tool calls with `async: true`, so they never block Claude Code. They log the completed tool call including the response.

Session state is written to a temp file (`/tmp/kontext/session-<pid>/`) and passed to hook subcommands via the `KONTEXT_SESSION_FILE` environment variable. The session is cleaned up on exit.

## Development

```bash
pnpm install
pnpm build          # build to dist/bin.mjs
pnpm check-types    # type check
pnpm lint           # eslint
```

## License

MIT
