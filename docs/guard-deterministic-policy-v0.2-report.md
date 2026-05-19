# Guard Deterministic Policy v0.2 Report

## Where We Were

The launch policy was too easy to bypass in strict mode because normalization removed all quoted shell text before deterministic rules ran. That avoided false positives in commit messages, but it also hid real execution payloads such as:

- `psql "$PROD_DATABASE_URL" -c "DROP DATABASE production;"`
- `mysql -e "DROP TABLE users"`
- managed MCP writes like `mcp__railway__restart_service`
- provider CLI mutations like `aws s3 rm s3://prod-bucket --recursive`

The result was a policy that looked strict in the dashboard but still allowed several high-impact infrastructure and database actions to reach the judge or execute in observe mode.

## Research Basis

- Claude Code `PreToolUse` hooks receive the tool name and input before execution, including Bash `command`, and can return `permissionDecision: "deny"` to block the call. Source: [Claude Code hooks reference](https://code.claude.com/docs/en/hooks).
- OWASP Agentic AI guidance recommends pre-execution validation, strict tool access controls, clear operational boundaries, and execution logs for AI tool calls. Source: [OWASP Agentic AI - Threats and Mitigations](https://genai.owasp.org/download/45674/?tmstv=1739819891).
- OWASP AIVSS calls out weak authorization for tool access as a path to unauthorized actions, data exposure, and infrastructure compromise. Source: [OWASP AIVSS v0.8](https://aivss.owasp.org/assets/publications/AIVSS%20Scoring%20System%20For%20OWASP%20Agentic%20AI%20Core%20Security%20Risks%20v0.8.pdf).
- Recent agentic-AI security research recommends evaluating posture with unsafe-action style metrics rather than only model-output quality. Source: [SoK: The Attack Surface of Agentic AI](https://arxiv.org/abs/2603.22928).

## What Changed

Policy version is now `guard-policy-v0.2.0`, with rule pack `v0.2.0`.

The v0.2 hard cutover improves deterministic coverage in four places:

- Shell normalization now preserves executable quoted payloads while still stripping text-only arguments for `git commit`, `gh pr create`, and search commands.
- Provider CLI classification now recognizes destructive database, AWS, Kubernetes, Terraform, Railway, Vercel, Docker, and database-client actions.
- Managed MCP tools are parsed by provider and action, so production writes are no longer treated as safe just because they are managed tools.
- Strict mode now denies remote source-control writes and direct infrastructure API mutations without explicit user intent.

## Evaluation

Command:

```sh
go test ./internal/guard/policy -run TestStrictPolicyEvaluationV02 -v
```

Result:

```text
strict policy v0.2 caught 14/14 deny fixtures; launch baseline caught 2/14
```

Coverage:

| Group | v0.2 strict result |
| --- | --- |
| Quoted SQL/database destruction | denied |
| Cloud/provider destructive mutations | denied |
| Managed production MCP mutations | denied |
| Credential file read/write | denied |
| Remote source-control writes | denied |
| Search/docs/commit false-positive traps | allowed |
| Local test and read-only inspection commands | allowed |

The key improvement is not adding a larger blocklist. It is preserving the action-bearing parts of a tool call while stripping metadata-like text that caused false positives.

## Verification

Targeted tests:

```sh
go test ./internal/guard/risk ./internal/guard/policy ./internal/guard/policyconfig ./internal/guard/app/server
```

Full evaluation test:

```sh
go test ./internal/guard/policy -run TestStrictPolicyEvaluationV02 -v
```

Repository verification:

```sh
go test ./...
go vet ./...
git diff --check
make guard-e2e
```

All checks passed locally.
