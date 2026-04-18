# Changelog

## [0.4.0](https://github.com/kontext-security/kontext-cli/compare/v0.3.0...v0.4.0) (2026-04-18)


### Features

* **cli:** add verbose diagnostics mode ([#68](https://github.com/kontext-security/kontext-cli/issues/68)) ([8de7536](https://github.com/kontext-security/kontext-cli/commit/8de75362722d35a2853e468036f2cf4ae34adf83))
* **cli:** prompt to upgrade when a new version is available ([#73](https://github.com/kontext-security/kontext-cli/issues/73)) ([85c791e](https://github.com/kontext-security/kontext-cli/commit/85c791e422d23db929eacaec5cbacf3cc2bb568b))
* **hooks:** quiet default allow reasons ([#71](https://github.com/kontext-security/kontext-cli/issues/71)) ([43d07a2](https://github.com/kontext-security/kontext-cli/commit/43d07a263ba1f05ba53d90bb9591fbc70968c503))


### Bug Fixes

* **auth:** reject gateway reauth account mismatch ([#69](https://github.com/kontext-security/kontext-cli/issues/69)) ([c000223](https://github.com/kontext-security/kontext-cli/commit/c000223230b300f89d2dcac0d19b5bfa0a8c3885))
* **auth:** use stable session identity ([#66](https://github.com/kontext-security/kontext-cli/issues/66)) ([60ba8f3](https://github.com/kontext-security/kontext-cli/commit/60ba8f351a3e37c1ed7b8aac8a030fda214b8198))
* **ci:** run release please with app token ([#74](https://github.com/kontext-security/kontext-cli/issues/74)) ([bba527b](https://github.com/kontext-security/kontext-cli/commit/bba527bc2ad2934e0b5fbf9a7188afc274d98f30))
* **cli:** harden hook and credential error handling ([#64](https://github.com/kontext-security/kontext-cli/issues/64)) ([bf33df7](https://github.com/kontext-security/kontext-cli/commit/bf33df74d204f89f4ff04a389755f26610344592))
* **start:** preflight agent launch setup ([#67](https://github.com/kontext-security/kontext-cli/issues/67)) ([c40cbeb](https://github.com/kontext-security/kontext-cli/commit/c40cbebaa6b522f1a0c27544249419df49356a63))
* **start:** summarize missing provider setup ([#70](https://github.com/kontext-security/kontext-cli/issues/70)) ([faab6fc](https://github.com/kontext-security/kontext-cli/commit/faab6fc0dcf956e184cd29a9eeceeb251688b375))

## [0.3.0](https://github.com/kontext-security/kontext-cli/compare/v0.2.2...v0.3.0) (2026-04-14)


### Features

* sync managed CLI env placeholders ([#61](https://github.com/kontext-security/kontext-cli/issues/61)) ([ccd60be](https://github.com/kontext-security/kontext-cli/commit/ccd60bef83b225c48088385b89b75d84b9a06a30))

## [0.2.2](https://github.com/kontext-security/kontext-cli/compare/v0.2.1...v0.2.2) (2026-04-14)


### Bug Fixes

* cut over github org and release links ([#58](https://github.com/kontext-security/kontext-cli/issues/58)) ([fa561fd](https://github.com/kontext-security/kontext-cli/commit/fa561fd4b09a09e0ce930e0a3f6f4f976e829ecb))

## [0.2.1](https://github.com/kontext-security/kontext-cli/compare/v0.2.0...v0.2.1) (2026-04-10)


### Bug Fixes

* handle provider required in hosted connect ([#52](https://github.com/kontext-security/kontext-cli/issues/52)) ([93bae50](https://github.com/kontext-security/kontext-cli/commit/93bae50afcefa1ccd56f76685eaeea4bee303d07))

## [0.2.0](https://github.com/kontext-security/kontext-cli/compare/v0.1.1...v0.2.0) (2026-04-09)


### Features

* **cli:** add logout command ([#46](https://github.com/kontext-security/kontext-cli/issues/46)) ([840c98c](https://github.com/kontext-security/kontext-cli/commit/840c98cec7eb85c8812b43664f02f3264e2cc340))
* **cli:** check for new releases on startup ([#48](https://github.com/kontext-security/kontext-cli/issues/48)) ([ef435d6](https://github.com/kontext-security/kontext-cli/commit/ef435d6e6cd0f74b9c0fe0291c9b66bb64c11440))


### Bug Fixes

* **cli:** exchange gateway token after agent auth ([#50](https://github.com/kontext-security/kontext-cli/issues/50)) ([77608e2](https://github.com/kontext-security/kontext-cli/commit/77608e2fbdcfad5448e3bc19f61c1bb53f1066ff))
* **cli:** scope exchanges to the session agent ([#47](https://github.com/kontext-security/kontext-cli/issues/47)) ([3c236bc](https://github.com/kontext-security/kontext-cli/commit/3c236bc239ad6e321d0bc8ed399bc0eb3174e0b5))
* **cli:** use agent-scoped gateway login for connect sessions ([#49](https://github.com/kontext-security/kontext-cli/issues/49)) ([0ab023c](https://github.com/kontext-security/kontext-cli/commit/0ab023cc5d336a3c03966ce6f8679f83ea80bc2a))
* use connect-session URL for provider auth ([8aeede0](https://github.com/kontext-security/kontext-cli/commit/8aeede08b0714c3af4ec55ed542816916b45630e))

## [0.1.1](https://github.com/kontext-security/kontext-cli/compare/v0.1.0...v0.1.1) (2026-04-09)


### Bug Fixes

* handle provider_reauthorization_required as reconnect-needed ([#27](https://github.com/kontext-security/kontext-cli/issues/27)) ([8e89e26](https://github.com/kontext-security/kontext-cli/commit/8e89e2674ac88f5fe2f8f5907034bd851a15ff97))
* harden CLI repo for public release ([075d44f](https://github.com/kontext-security/kontext-cli/commit/075d44ffd014a911ef6a8e63a19d7868cfbc407b))

## 0.1.0 (2026-04-09)


### Features

* implement kontext login — OIDC PKCE with system keyring ([c692eb5](https://github.com/kontext-security/kontext-cli/commit/c692eb5c6de63534a128ea977d72b3d46692ae8f))
* implement kontext start — unified first-run experience ([067d199](https://github.com/kontext-security/kontext-cli/commit/067d199b6c507b5ab20541c75fec808246219189))
* initial CLI package — kontext start with Claude Code hooks ([6f3e99f](https://github.com/kontext-security/kontext-cli/commit/6f3e99fe32a286f500404b7b7d6c21542c282096))
* interactive template creation on first run ([3e55beb](https://github.com/kontext-security/kontext-cli/commit/3e55beb5047a466c2e26ca7c4bb3ca09f1447cb8))
* rewrite CLI in Go with protobuf service definitions ([a6e6c3d](https://github.com/kontext-security/kontext-cli/commit/a6e6c3d109c9e046abeb10611a46168bcd3200d0))
* wire full governance telemetry pipeline ([#3](https://github.com/kontext-security/kontext-cli/issues/3)) ([bd16ef2](https://github.com/kontext-security/kontext-cli/commit/bd16ef281e8fc6dda1e45154e63a27fa56fbc526))
* wire up credential exchange via RFC 8693 + OIDC token refresh ([#7](https://github.com/kontext-security/kontext-cli/issues/7)) ([0eb1840](https://github.com/kontext-security/kontext-cli/commit/0eb184021a8416d8e270113576d333d7571d4b38))


### Bug Fixes

* **ci:** pass github_token to buf-setup-action ([#5](https://github.com/kontext-security/kontext-cli/issues/5)) ([13e1f89](https://github.com/kontext-security/kontext-cli/commit/13e1f89e64baa80a90951eb367ebda56dca2de1c))
* default API URL to api.kontext.security ([4907c76](https://github.com/kontext-security/kontext-cli/commit/4907c76143fd120058af760628dc20ab99991889))
* gitignore .env.kontext (user-specific) ([590f451](https://github.com/kontext-security/kontext-cli/commit/590f451a640f05e7964e00e282e2a6f02ffc8d13))
* launch agent without template instead of blocking ([5293c6b](https://github.com/kontext-security/kontext-cli/commit/5293c6b20acfb25db897aee3d1ce6487f24347b1))
* pass full parent env to agent subprocess ([318fb77](https://github.com/kontext-security/kontext-cli/commit/318fb77c2dfdc5cef9ee99b11295c5d9c78d3015))
* propagate IngestEvent errors and document HTTP/2 requirement ([#15](https://github.com/kontext-security/kontext-cli/issues/15)) ([5e7e2e2](https://github.com/kontext-security/kontext-cli/commit/5e7e2e2eb757dfd990e9b9487559e6ba39f4612a))
* remove Setpgid — let agent control the terminal ([b2b4478](https://github.com/kontext-security/kontext-cli/commit/b2b447856f3a294ceae98b4d65ec66678124651e))
* replace interactive init with dashboard pointer ([ab3b1e3](https://github.com/kontext-security/kontext-cli/commit/ab3b1e30e8516e323feb006009f66f0afabf6fec))
* skip failed credential exchanges instead of aborting ([747184d](https://github.com/kontext-security/kontext-cli/commit/747184dbcc9bb17545afceff3da3c35c67c9a263))
* use buf managed mode for go_package override ([#6](https://github.com/kontext-security/kontext-cli/issues/6)) ([dcc9d7a](https://github.com/kontext-security/kontext-cli/commit/dcc9d7a49117d4ee20d1a7ffe2ee50ca602f17f0))
* use OAuth authorization server metadata instead of OIDC discovery ([acd0cde](https://github.com/kontext-security/kontext-cli/commit/acd0cde591d9fe5f7e4a410dfd1e01e39643e0d9))
