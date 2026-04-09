# Changelog

## 1.0.0 (2026-04-09)


### Features

* implement kontext login — OIDC PKCE with system keyring ([c692eb5](https://github.com/kontext-dev/kontext-cli/commit/c692eb5c6de63534a128ea977d72b3d46692ae8f))
* implement kontext start — unified first-run experience ([067d199](https://github.com/kontext-dev/kontext-cli/commit/067d199b6c507b5ab20541c75fec808246219189))
* initial CLI package — kontext start with Claude Code hooks ([6f3e99f](https://github.com/kontext-dev/kontext-cli/commit/6f3e99fe32a286f500404b7b7d6c21542c282096))
* interactive template creation on first run ([3e55beb](https://github.com/kontext-dev/kontext-cli/commit/3e55beb5047a466c2e26ca7c4bb3ca09f1447cb8))
* rewrite CLI in Go with protobuf service definitions ([a6e6c3d](https://github.com/kontext-dev/kontext-cli/commit/a6e6c3d109c9e046abeb10611a46168bcd3200d0))
* wire full governance telemetry pipeline ([#3](https://github.com/kontext-dev/kontext-cli/issues/3)) ([bd16ef2](https://github.com/kontext-dev/kontext-cli/commit/bd16ef281e8fc6dda1e45154e63a27fa56fbc526))
* wire up credential exchange via RFC 8693 + OIDC token refresh ([#7](https://github.com/kontext-dev/kontext-cli/issues/7)) ([0eb1840](https://github.com/kontext-dev/kontext-cli/commit/0eb184021a8416d8e270113576d333d7571d4b38))


### Bug Fixes

* **ci:** pass github_token to buf-setup-action ([#5](https://github.com/kontext-dev/kontext-cli/issues/5)) ([13e1f89](https://github.com/kontext-dev/kontext-cli/commit/13e1f89e64baa80a90951eb367ebda56dca2de1c))
* default API URL to api.kontext.security ([4907c76](https://github.com/kontext-dev/kontext-cli/commit/4907c76143fd120058af760628dc20ab99991889))
* gitignore .env.kontext (user-specific) ([590f451](https://github.com/kontext-dev/kontext-cli/commit/590f451a640f05e7964e00e282e2a6f02ffc8d13))
* launch agent without template instead of blocking ([5293c6b](https://github.com/kontext-dev/kontext-cli/commit/5293c6b20acfb25db897aee3d1ce6487f24347b1))
* pass full parent env to agent subprocess ([318fb77](https://github.com/kontext-dev/kontext-cli/commit/318fb77c2dfdc5cef9ee99b11295c5d9c78d3015))
* propagate IngestEvent errors and document HTTP/2 requirement ([#15](https://github.com/kontext-dev/kontext-cli/issues/15)) ([5e7e2e2](https://github.com/kontext-dev/kontext-cli/commit/5e7e2e2eb757dfd990e9b9487559e6ba39f4612a))
* remove Setpgid — let agent control the terminal ([b2b4478](https://github.com/kontext-dev/kontext-cli/commit/b2b447856f3a294ceae98b4d65ec66678124651e))
* replace interactive init with dashboard pointer ([ab3b1e3](https://github.com/kontext-dev/kontext-cli/commit/ab3b1e30e8516e323feb006009f66f0afabf6fec))
* skip failed credential exchanges instead of aborting ([747184d](https://github.com/kontext-dev/kontext-cli/commit/747184dbcc9bb17545afceff3da3c35c67c9a263))
* use buf managed mode for go_package override ([#6](https://github.com/kontext-dev/kontext-cli/issues/6)) ([dcc9d7a](https://github.com/kontext-dev/kontext-cli/commit/dcc9d7a49117d4ee20d1a7ffe2ee50ca602f17f0))
* use OAuth authorization server metadata instead of OIDC discovery ([acd0cde](https://github.com/kontext-dev/kontext-cli/commit/acd0cde591d9fe5f7e4a410dfd1e01e39643e0d9))
