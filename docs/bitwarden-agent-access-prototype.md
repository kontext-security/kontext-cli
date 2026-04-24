# Bitwarden Agent Access Prototype

This worktree includes an experimental local-direct Bitwarden resolver for `kontext-cli`.

It keeps the normal Kontext session and hook-governance flow, but resolves selected env vars
through `aac connect --output json` using a stored reusable PSK instead of a fresh rendezvous
code on every launch.

## Status

- Experimental
- Local-only
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

Pair once locally:

```bash
kontext bitwarden pair --token "<reusable-psk-token>"
```

Optional environment variables:

```bash
export KONTEXT_BITWARDEN_AAC_BIN=aac
```

Notes:

- The reusable PSK token should come from `aac listen --reusable-psk`.
- Once stored, the CLI reuses it automatically for Bitwarden placeholders.
- `KONTEXT_BITWARDEN_AAC_BIN` overrides the `aac` binary path.
- `aac` still needs to be installed and usable at `kontext start` time.
- The Bitwarden listener still needs to be running and unlocked when credentials are resolved.

## Local Tryout

1. Install `aac` and ensure Bitwarden CLI support is configured.
2. Start the local Bitwarden side:

```bash
aac listen --reusable-psk
```

3. Store the PSK token once:

```bash
kontext bitwarden pair --token "<reusable-psk-token>"
```

4. Add `bitwarden` placeholders to `.env.kontext`.
5. Run:

```bash
kontext start --agent claude
```

## Trust Model

This prototype uses two different credential paths:

- `kontext`: backend-governed token exchange
- `bitwarden`: local-direct vault access through Agent Access

They are intentionally not treated as the same trust class.
