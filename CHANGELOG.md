# Changelog

## [0.10.0](https://github.com/kontext-security/kontext-cli/compare/v0.9.0...v0.10.0) (2026-06-18)


### Features

* **managedstream:** add daemon heartbeats ([#301](https://github.com/kontext-security/kontext-cli/issues/301)) ([0d0ce2e](https://github.com/kontext-security/kontext-cli/commit/0d0ce2eb5c5a201fe476dfe4628e2d8a75e6d367))


### Bug Fixes

* **managedobserve:** refresh install token per flush ENG-446 ([ad6a795](https://github.com/kontext-security/kontext-cli/commit/ad6a79554aebac4e873bb2814d1a55e491ce4855))
* **setup:** clarify daemon wait state ([72164b8](https://github.com/kontext-security/kontext-cli/commit/72164b87aea22cb9bd1ef17c456de5f27620cfda))

## [0.9.0](https://github.com/kontext-security/kontext-cli/compare/v0.8.1...v0.9.0) (2026-06-18)


### Features

* **cowork:** observe Claude Cowork tool calls via per-session settings injection ([#283](https://github.com/kontext-security/kontext-cli/issues/283)) ([0751807](https://github.com/kontext-security/kontext-cli/commit/0751807868fff89c07d5b5ca0f75971bb7c5a280))
* **githubpolicy:** evaluate synced GitHub policy locally in observer mode (ENG-426) ([#279](https://github.com/kontext-security/kontext-cli/issues/279)) ([ab2010f](https://github.com/kontext-security/kontext-cli/commit/ab2010f53cf5f37dfd33a706608e79152af1e09b))
* **managedobserve:** add daemon lifecycle ([#193](https://github.com/kontext-security/kontext-cli/issues/193)) ([a8dfd0e](https://github.com/kontext-security/kontext-cli/commit/a8dfd0ebba4d04dfc2fe98d13e85838a09ce913b))
* **managed:** report deployed package version to ledger ([#232](https://github.com/kontext-security/kontext-cli/issues/232)) ([6a8c3b1](https://github.com/kontext-security/kontext-cli/commit/6a8c3b174d3f675c2216514fb1044676bf710921))
* **managed:** stream ledger batches to hosted backend ([#196](https://github.com/kontext-security/kontext-cli/issues/196)) ([2696a62](https://github.com/kontext-security/kontext-cli/commit/2696a62b30d11a779f904ef15dced1c09a26c84c))
* **observe:** surface revoked install tokens; doctor managed-observe section ([#278](https://github.com/kontext-security/kontext-cli/issues/278)) ([7c9b80a](https://github.com/kontext-security/kontext-cli/commit/7c9b80a34fc8ffe0571a22d83d9353104d091fc4))
* **selfserve:** scope-aware config/identity paths, user settings merge, version fallback ([#276](https://github.com/kontext-security/kontext-cli/issues/276)) ([5476754](https://github.com/kontext-security/kontext-cli/commit/547675444d906d031a2238b7a6c3eb4f8f5f01be))
* **setup:** kontext setup / --uninstall for self-serve managed observe ([#277](https://github.com/kontext-security/kontext-cli/issues/277)) ([7963e30](https://github.com/kontext-security/kontext-cli/commit/7963e302fa214a3189014abe4eb7d330af251915))


### Bug Fixes

* **clawpatch:** address daily finding ([#199](https://github.com/kontext-security/kontext-cli/issues/199)) ([fe9631c](https://github.com/kontext-security/kontext-cli/commit/fe9631c53fbfbaf71c4e12d647d3b940d3623a73))
* **clawpatch:** address daily finding ([#215](https://github.com/kontext-security/kontext-cli/issues/215)) ([a407b1d](https://github.com/kontext-security/kontext-cli/commit/a407b1d47fa536b79fc490ebca65193f69093ce6))
* **cli:** emit canonical access control events ([#223](https://github.com/kontext-security/kontext-cli/issues/223)) ([261f238](https://github.com/kontext-security/kontext-cli/commit/261f238eee169e5ac68404baf4dc43a628b3ae71))
* **hook:** decode array tool_response from MCP tools ([#246](https://github.com/kontext-security/kontext-cli/issues/246)) ([53974e7](https://github.com/kontext-security/kontext-cli/commit/53974e7808c4a28e52a03b3bcfb0987795065acb))
* **managed:** gate managed loopback HTTP config ([#233](https://github.com/kontext-security/kontext-cli/issues/233)) ([fb3fb85](https://github.com/kontext-security/kontext-cli/commit/fb3fb85198ac56e050fd34ea601449640511fbda))
* **managedobserve:** avoid startup db lock ([#195](https://github.com/kontext-security/kontext-cli/issues/195)) ([aa5cffa](https://github.com/kontext-security/kontext-cli/commit/aa5cffaec5b65d0e1a630f7e4c030bb47ddaa8dc))
* **managedstream:** split hosted ingest batches ([#260](https://github.com/kontext-security/kontext-cli/issues/260)) ([a78e44a](https://github.com/kontext-security/kontext-cli/commit/a78e44aa7b7140bf27d16b5b48880d4e47c63101))
* **managedstream:** use fixed ledger timestamp cursors ([#267](https://github.com/kontext-security/kontext-cli/issues/267)) ([2378437](https://github.com/kontext-security/kontext-cli/commit/237843747ea98179fdd0f404a1d4551ff1be005e))
* optimize guard risk provider classification ([#221](https://github.com/kontext-security/kontext-cli/issues/221)) ([3350778](https://github.com/kontext-security/kontext-cli/commit/33507786704c0d9aba49923cd3e6bbd25f4485e9))
* optimize internal/guard/risk signal deduping ([#198](https://github.com/kontext-security/kontext-cli/issues/198)) ([0ba34ea](https://github.com/kontext-security/kontext-cli/commit/0ba34ea63f6a4975d445cf7944b0d78c97b10300))
* optimize managed settings validation scan ([#214](https://github.com/kontext-security/kontext-cli/issues/214)) ([ddff856](https://github.com/kontext-security/kontext-cli/commit/ddff8567876c84d01b7d408085eb7e070f7e393e))
* **selfserve:** harden managed observe cli readiness ([#286](https://github.com/kontext-security/kontext-cli/issues/286)) ([3befe3e](https://github.com/kontext-security/kontext-cli/commit/3befe3eb6565507a28c336b70dfa2378ed27e893))

## [0.8.1](https://github.com/kontext-security/kontext-cli/compare/v0.8.0...v0.8.1) (2026-05-20)


### Bug Fixes

* reflect guard mode in dashboard ([#190](https://github.com/kontext-security/kontext-cli/issues/190)) ([7540b9d](https://github.com/kontext-security/kontext-cli/commit/7540b9d30ee25e3dba9443c1e240d009f14199cc))

## [0.8.0](https://github.com/kontext-security/kontext-cli/compare/v0.7.0...v0.8.0) (2026-05-20)


### Features

* **claude:** add managed settings contract ([#179](https://github.com/kontext-security/kontext-cli/issues/179)) ([0d4f469](https://github.com/kontext-security/kontext-cli/commit/0d4f4690bfb2b1c5f67295fda412a878d92e2607))
* **claude:** expose managed settings CLI ([#180](https://github.com/kontext-security/kontext-cli/issues/180)) ([82539d6](https://github.com/kontext-security/kontext-cli/commit/82539d660efb5fb89b1d82c6f2a13283d36acd53))
* **claudemanaged:** mark lifecycle hooks async ([#189](https://github.com/kontext-security/kontext-cli/issues/189)) ([de5d20c](https://github.com/kontext-security/kontext-cli/commit/de5d20c47e79a99dfd394f051d831ea578fe7f8b))
* **guard-dashboard:** split decision log from observed activity ([#186](https://github.com/kontext-security/kontext-cli/issues/186)) ([1ef9bf1](https://github.com/kontext-security/kontext-cli/commit/1ef9bf141a391b527d5f5702d350e7efb42c6fdd))
* **guard:** add authorization ledger ([#178](https://github.com/kontext-security/kontext-cli/issues/178)) ([02e4300](https://github.com/kontext-security/kontext-cli/commit/02e43008e794b42a278359097960a10ca4ce6564))
* **guard:** improve local judge startup progress ([#188](https://github.com/kontext-security/kontext-cli/issues/188)) ([66b9a43](https://github.com/kontext-security/kontext-cli/commit/66b9a435a91bee77256a0952bf31933795d1b8dd))
* **managed:** add installation identity store ([#176](https://github.com/kontext-security/kontext-cli/issues/176)) ([958c2c1](https://github.com/kontext-security/kontext-cli/commit/958c2c1883434595324508dbe40984eca41d9cdc))
* **managed:** add managed config contract ([#175](https://github.com/kontext-security/kontext-cli/issues/175)) ([213b6a6](https://github.com/kontext-security/kontext-cli/commit/213b6a67b1ea7f6eea118b670e832de6e3f0002a))


### Bug Fixes

* **ENG-332:** remove macOS guard notifications ([#163](https://github.com/kontext-security/kontext-cli/issues/163)) ([487daaa](https://github.com/kontext-security/kontext-cli/commit/487daaa91f557d5a69d31e487ee536adc398bfde))
* optimize internal/credential template entry ordering ([#182](https://github.com/kontext-security/kontext-cli/issues/182)) ([5244bdd](https://github.com/kontext-security/kontext-cli/commit/5244bddb605d0a5fa4f04f7aae5e6f08043b6b88))

## [0.7.0](https://github.com/kontext-security/kontext-cli/compare/v0.6.0...v0.7.0) (2026-05-18)


### Features

* add local guard judge contract ([#132](https://github.com/kontext-security/kontext-cli/issues/132)) ([ef6a3cd](https://github.com/kontext-security/kontext-cli/commit/ef6a3cd1c1cfba54e3c4e8c645c27b3c7829a5c3))
* **cli:** make kontext start local-first ([#140](https://github.com/kontext-security/kontext-cli/issues/140)) ([02a34bf](https://github.com/kontext-security/kontext-cli/commit/02a34bfaf553a7d7dd5adf2fa4fba09168bd7667))
* **dashboard:** show guard diagnostics ([#156](https://github.com/kontext-security/kontext-cli/issues/156)) ([dcbdf4a](https://github.com/kontext-security/kontext-cli/commit/dcbdf4a3925a21c7605a65001617cb75d57f6182))
* **guard:** add deterministic policy engine ([#131](https://github.com/kontext-security/kontext-cli/issues/131)) ([3a0f16e](https://github.com/kontext-security/kontext-cli/commit/3a0f16e94cb205b317a0f8d8d42e2ba66096f452))
* **guard:** add policy config store ([#135](https://github.com/kontext-security/kontext-cli/issues/135)) ([520c3b6](https://github.com/kontext-security/kontext-cli/commit/520c3b679421d36ef79fe2430441e7dc10abe057))
* **guard:** add policy profile dashboard ([#137](https://github.com/kontext-security/kontext-cli/issues/137)) ([0b0e856](https://github.com/kontext-security/kontext-cli/commit/0b0e856c8f63bbf3ee321bf319d789968e1488de))
* **guard:** connect deterministic policy and judge ([#154](https://github.com/kontext-security/kontext-cli/issues/154)) ([25f0d32](https://github.com/kontext-security/kontext-cli/commit/25f0d32707b2de240d5907d4ca542166c0b074b5))
* manage local judge runtime ([#136](https://github.com/kontext-security/kontext-cli/issues/136)) ([09f4fc0](https://github.com/kontext-security/kontext-cli/commit/09f4fc070146b0ad1924f82b6ac23b26ade079bd))
* **runtime service:** Guard now starts a Unix-socket localruntime.Service alongside the existing HTTP daemon ([#122](https://github.com/kontext-security/kontext-cli/issues/122)) ([3e87e12](https://github.com/kontext-security/kontext-cli/commit/3e87e12ae91dd9a2546b816b6b1b38b2cc4a8289))
* **runtime service:** Introduce runtime service and make existing Unix socket more generic ([#121](https://github.com/kontext-security/kontext-cli/issues/121)) ([2bbaa93](https://github.com/kontext-security/kontext-cli/commit/2bbaa933273dd8f7bd39af03849f5c638db1c974))


### Bug Fixes

* **dashboard:** contain command drawer text ([#157](https://github.com/kontext-security/kontext-cli/issues/157)) ([4107e31](https://github.com/kontext-security/kontext-cli/commit/4107e319b180f85fb936f8b8d6d66a0bf79fb435))
* **dashboard:** polish activity summary and log groups ([#153](https://github.com/kontext-security/kontext-cli/issues/153)) ([fc79101](https://github.com/kontext-security/kontext-cli/commit/fc7910160ed271e816acf3439eef0d8be48a16e9))
* harden npm dependency resolution ([#114](https://github.com/kontext-security/kontext-cli/issues/114)) ([86eadf5](https://github.com/kontext-security/kontext-cli/commit/86eadf512d35ddb329f53fb9d24a61e561a260db))
* optimize judge fixture category matching ([#146](https://github.com/kontext-security/kontext-cli/issues/146)) ([0bad7ab](https://github.com/kontext-security/kontext-cli/commit/0bad7ab17c71be2c2ec8b35b39da79a37b0a2410))
* **repo:** remove repo-wide codeowners ([#133](https://github.com/kontext-security/kontext-cli/issues/133)) ([73557f0](https://github.com/kontext-security/kontext-cli/commit/73557f0dd0b47f1b6da0a69f36eb8168fa981455))

## [0.6.0](https://github.com/kontext-security/kontext-cli/compare/v0.5.1...v0.6.0) (2026-05-03)


### Features

* add hosted hook sidecar transport ([#94](https://github.com/kontext-security/kontext-cli/issues/94)) ([22873e7](https://github.com/kontext-security/kontext-cli/commit/22873e79e648b36a7327903cb9415fac82a063f4))
* share claude hook runtime ([#93](https://github.com/kontext-security/kontext-cli/issues/93)) ([500bc71](https://github.com/kontext-security/kontext-cli/commit/500bc71e4e779883e511177091eb2583ed269312))

## [0.5.1](https://github.com/kontext-security/kontext-cli/compare/v0.5.0...v0.5.1) (2026-05-01)


### Bug Fixes

* add exponential backoff to sidecar heartbeat loop ([#88](https://github.com/kontext-security/kontext-cli/issues/88)) ([b166c9d](https://github.com/kontext-security/kontext-cli/commit/b166c9d4251c493f8408de6657f96d14321252dd))

## [0.5.0](https://github.com/kontext-security/kontext-cli/compare/v0.4.0...v0.5.0) (2026-05-01)


### Features

* add local Guard mode ([#82](https://github.com/kontext-security/kontext-cli/issues/82)) ([d957510](https://github.com/kontext-security/kontext-cli/commit/d957510dda4361f9a333a7697e11154b9f0c9fcf))
* **cli:** forward Claude hook metadata ([#81](https://github.com/kontext-security/kontext-cli/issues/81)) ([fb254b3](https://github.com/kontext-security/kontext-cli/commit/fb254b3500b3e77d0b27bb93ab53dfb23741e580))
* **run:** require successful BootstrapCli before launching runtime ([#78](https://github.com/kontext-security/kontext-cli/issues/78)) ([a0ce263](https://github.com/kontext-security/kontext-cli/commit/a0ce263129faed71e4e1920e230ad9e015d73900))


### Bug Fixes

* auto-refresh OIDC token with proactive + reactive strategy ([#17](https://github.com/kontext-security/kontext-cli/issues/17)) ([c5492d3](https://github.com/kontext-security/kontext-cli/commit/c5492d36a14acc5b412a41f0a9815c706255218b))

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
