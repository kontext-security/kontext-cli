# Staging CLI builds

A staging channel for testing a CLI branch against the **staging backend**
before the branch lands on `main` and becomes a prod release.

- **Prod:** `brew install kontext-security/tap/kontext` — built from `main`
  by release-please, public assets on this repo's releases.
- **Staging:** `brew install kontext-security/tap/kontext-staging` — built
  on demand from any branch via the `Staging Release` workflow, assets in the
  **private** `kontext-security/kontext-cli-staging-releases` repo (org
  members only). Staging tags are valid SemVer prereleases such as
  `v0.0.0-staging.20260721.4`. They are published only to the separate
  staging-releases repo, so release-please in the source repo never sees them.

The staging formula installs the same `kontext` binary as prod, so the two
formulae `conflicts_with` each other — uninstall one before installing the
other.

## Publishing a staging build

Prerequisites (one-time, repo admins):

1. The private repo `kontext-security/kontext-cli-staging-releases` exists.
2. The `kontext-release-bot` GitHub App (the same app release-please uses
   for prod releases) is installed on that repo with Contents: read & write
   (org Settings → GitHub Apps → kontext-release-bot → Configure →
   Repository access). The workflow mints a short-lived per-run token from
   the app's existing credentials — no PATs or extra secrets involved.

Then, from any branch:

```bash
gh workflow run staging-release.yml -R kontext-security/kontext-cli \
  -f ref=my-feature-branch
```

(or Actions → Staging Release → Run workflow). The workflow builds all
platform tarballs, creates a prerelease in the private repo, and updates
`Formula/kontext-staging.rb` in `kontext-security/homebrew-tap`. Re-run it to
publish a newer build; the version (`0.0.0-staging.YYYYMMDD.RUN`) increases
monotonically so `brew upgrade kontext-staging` picks it up.

## Installing and testing

Requires a GitHub account with read access to the private staging-releases
repo (org members). Homebrew needs that account's token to download assets:

```bash
# one-time
gh auth login

brew uninstall kontext 2>/dev/null || true   # conflicts_with prod
HOMEBREW_GITHUB_API_TOKEN="$(gh auth token)" \
  brew install kontext-security/tap/kontext-staging

# point the CLI at the staging backend before setup
export KONTEXT_API_URL=https://api.staging.kontext.security
kontext setup \
  --cloud-url https://api.staging.kontext.security \
  --token <staging-token>
```

`HOMEBREW_GITHUB_API_TOKEN` must be set on every `install`/`upgrade` — the
formula's error message repeats the incantation if you forget.

To go back to prod:

```bash
brew uninstall kontext-staging
brew install kontext-security/tap/kontext
```

## Promoting to prod

There is no separate promote step: merge the tested branch to `main` as usual
and release-please cuts the next prod release. Staging prereleases accumulate
in the private repo as throwaway artifacts; prune old ones occasionally.

## Caveats

- The binary still defaults to production. Export `KONTEXT_API_URL` for CLI
  commands. `kontext setup` respects that variable too; passing `--cloud-url`
  explicitly, as shown above, also persists the staging URL for the managed
  background agent.
- The staging backend hostname is not secret — it appears in this public
  repo. The private-releases mechanism only gates the binaries, not the
  topology.
