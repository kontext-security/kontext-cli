# Kontext Guard

Guard is the local safety mode inside `kontext`.

It lets a developer run Claude Code normally while Kontext watches tool calls locally, redacts captured data, scores risk, stores events in local SQLite, and shows a local dashboard with `would allow`, `would ask`, and `would deny` decisions.

## User path

```bash
brew install kontext-security/tap/kontext
kontext guard start
claude
```

Until the Guard PR is merged and released, test from source:

```bash
go run ./cmd/kontext guard start
claude
```

## Hermes Agent

Hermes Agent can run under the local Kontext runtime with the Hermes shell-hook adapter:

```bash
kontext start --agent hermes
KONTEXT_MODE=enforce kontext start --agent hermes
```

Kontext creates a per-session temporary Hermes home shaped as a Hermes profile, snapshots the required Hermes config/auth/env state, and writes temporary shell-hook config that points back to the local Kontext socket. It does not edit `~/.hermes/config.yaml`, does not preserve user-defined shell hooks in the generated session config, and pre-approves only the generated Kontext hook commands in the temporary allowlist.

In observe mode, the generated Hermes hook config uses this shape. Enforce sessions use `--mode enforce` in the same command positions:

```yaml
hooks:
  pre_tool_call:
    - command: "kontext hook --agent hermes --mode observe --socket /tmp/kontext/.../kontext.sock"
      timeout: 20
  post_tool_call:
    - command: "kontext hook --agent hermes --mode observe --socket /tmp/kontext/.../kontext.sock"
      timeout: 20
```

Current limitations:

- `ask` approval is not supported through Hermes shell hooks. In observe mode, Kontext records would-ask decisions. In enforce mode, Kontext maps `ask` and `deny` decisions to a Hermes block response.
- `updatedInput` is not supported through Hermes shell hooks.
- Managed sessions remain Claude-only.
- If Hermes cannot run the hook subprocess, the hook times out, or the hook emits malformed output, Hermes logs the problem and continues the agent loop.

## Runtime boundary

Guard mode is local-first by default:

- no login
- no hosted Kontext API
- no trace upload by default
- local daemon on `127.0.0.1:4765`
- local SQLite database
- embedded local dashboard
- observe mode by default

Hosted mode remains separate:

```bash
kontext start --managed
```

Hosted mode owns login, provider connection, short-lived scoped credentials, hosted traces, and team governance.

## Flow

```text
Claude Code
  -> kontext hook --agent claude --mode observe
  -> local runtime Unix socket
  -> RuntimeCore
  -> deterministic risk rules
  -> optional local LLM judge or Markov-chain risk model
  -> local SQLite
  -> local dashboard + notifications
```

## Risk layers

Guard uses two layers:

1. Deterministic rules for obvious risk, such as credential access, direct provider API calls with credential material, production mutations, and destructive persistent-resource operations.
2. A local Markov-chain risk model for sequence context in coding-agent workflows.

The shipped model is a JSON artifact under `models/guard/`. Lab is the private pipeline that ingests datasets and local traces, evaluates candidate models, and produces improved JSON files. Accepted model files are committed back to this repo by PR.

## Local judge

Guard can optionally call a localhost OpenAI-compatible judge, such as `llama-server`, after deterministic rules allow a blocking tool call:

```bash
kontext guard start \
  --judge-url http://127.0.0.1:8080 \
  --judge-model qwen3-0.6b-q4
```

Guard can also manage `llama-server` itself. This downloads the selected GGUF into the Kontext model cache when it is missing, starts `llama-server` on loopback, waits for `/v1/models`, and shuts the child process down with Guard:

```bash
kontext guard start --judge-managed
```

Use `--judge-port` or a loopback `--judge-url` such as `http://127.0.0.1:18081` to choose a different managed `llama-server` port.

The managed default is `Qwen/Qwen3-0.6B-GGUF` with `Qwen3-0.6B-Q8_0.gguf`. Override it with either a local model path:

```bash
kontext guard start \
  --judge-managed \
  --judge-model-path ~/.config/kontext/judge-models/qwen.gguf
```

Or a specific Hugging Face GGUF:

```bash
kontext guard start \
  --judge-managed \
  --judge-hf-repo Qwen/Qwen3-0.6B-GGUF \
  --judge-hf-file Qwen3-0.6B-Q8_0.gguf
```

Use `--judge-hf-revision` when the GGUF is on a Hugging Face branch, tag, commit, or ref other than `main`.

The judge receives a small redacted JSON input with tool metadata, normalized risk fields, deterministic policy context, and no full conversation history. It must return structured JSON with `decision` set to `allow` or `deny`. `ask` is not part of the judge contract.

Judge failures are fail-open for launch. If the local runtime is unavailable, times out, or returns invalid JSON, Guard records `judge_unavailable_allow` plus high-level metadata and allows the tool call. Judge URLs must point at localhost.

Evaluate a local judge against the launch fixtures:

```bash
kontext guard judge eval \
  --judge-url http://127.0.0.1:8080 \
  --judge-model Qwen/Qwen3-0.6B-GGUF \
  --fixtures internal/guard/judge/testdata/launch-v0.jsonl
```

The eval command is for local model and prompt iteration. It skips fixtures
where deterministic policy is expected to deny before the judge is called.

## Public/private boundary

Public in `kontext-cli`:

- `kontext guard ...` commands
- Claude Code local hook adapter
- local daemon, SQLite store, dashboard, notifications
- deterministic risk rules
- shipped baseline/candidate model JSON files

Private in Lab:

- dataset ingestion
- OpenTelemetry/Claude trace import
- weak labeling
- model training/evaluation
- model promotion gates
- unpublished datasets and experiments

## Work tracking

Linear is the front door for planning. GitHub issues and Linear issues should sync.

- Linear project: `Kontext CLI`
- GitHub label: `area:kontext`
- Private pipeline project: `Lab / Model Pipeline`

Done means:

- issue has acceptance criteria
- PR links the issue
- tests pass
- this file or the Linear Excalidraw link is updated if architecture changed
