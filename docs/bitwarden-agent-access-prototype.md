# Bitwarden Agent Access Prototype

This worktree includes an experimental local-direct Bitwarden resolver for `kontext-cli`.

It keeps the normal Kontext session and hook-governance flow, but resolves selected env vars
through `aac connect --output json` instead of Kontext RFC 8693 token exchange.

## Status

- Experimental
- Local-only
- Not pushed
- Intended for partnership and DX evaluation

## Placeholder Syntax

Use explicit `bitwarden` placeholders in `.env.kontext`:

```dotenv
GITHUB_TOKEN={{bitwarden:domain:github.com/password}}
DB_USER={{bitwarden:id:YOUR_ITEM_ID/username}}
DB_PASSWORD={{bitwarden:id:YOUR_ITEM_ID/password}}
```

Rules:

- `{{bitwarden:<domain>}}` defaults to the `password` field.
- `{{bitwarden:domain:<domain>/password}}` fetches by domain.
- `{{bitwarden:id:<item-id>/username}}` fetches by Bitwarden item id.
- Supported fields: `username`, `password`, `totp`, `uri`, `notes`, `domain`, `credential_id`

## Environment

Optional environment variables:

```bash
export KONTEXT_BITWARDEN_AAC_BIN=aac
export KONTEXT_BITWARDEN_PROVIDER=bitwarden
export KONTEXT_BITWARDEN_TOKEN="<pairing-token>"
```

Notes:

- `KONTEXT_BITWARDEN_TOKEN` lets the CLI pair and fetch in one step.
- If your `aac` setup already has an active connection, the token may not be needed.
- `KONTEXT_BITWARDEN_PROVIDER` is passed through to `aac` when set.

## Local Tryout

1. Install `aac` and ensure Bitwarden CLI support is configured.
2. Start the local Bitwarden side:

```bash
aac listen
```

3. Copy the pairing token if your setup requires one.
4. Add `bitwarden` placeholders to `.env.kontext`.
5. Export `KONTEXT_BITWARDEN_TOKEN` if needed.
6. Run:

```bash
kontext start --agent claude
```

## Trust Model

This prototype uses two different credential paths:

- `kontext`: backend-governed token exchange
- `bitwarden`: local-direct vault access through Agent Access

They are intentionally not treated as the same trust class.
