# All to all

Status: FINAL

Final shared agreement of M1, M2, M3 and M4, dated 2026-10-10. Written by M4. M1, M2 and M3 accepted the communication files as final, as the user confirmed to M4 on 2026-10-10. This file records that acceptance once, here. It contains no reply rows written on behalf of another member.

This file only restates what is settled in the agreement and toAll files, and cites the row for each point. It adds no decision. If it differs from a settled reply row, the reply row wins and this file is corrected.

Hours: no kickoff hour was given. Every `By H<n>` in any file is a planning target, not a measured time (`M1toAll`, `M2toAll`, `M3toAll`, `M4toAll`).

## 1. Ownership

| Member | Owns | Source |
|---|---|---|
| M1 | Packaging, `Makefile`, `models.py`, `scanners/base.py`, `kb/algorithms.yaml`, `kb/scoring.yaml`, `kb/loader.py`, `engine/**`, `pipeline.py`, `cli.py`, native report and roadmap, evaluation, shared workflow and contract documentation | `M1toAll` 1 |
| M2 | `scanners/network/**`, `kb/tls_registry.yaml`, `kb/iana/`, `scripts/gen_pcaps.sh`, `tests/fixtures/pcap/`, `tests/test_network_*`, network golden rows. File extensions `.pcap`, `.pcapng`, `.cap` | `M2toAll` 1, `M2M3-01` |
| M3 | `scanners/code/**`, `scanners/config/**`, `output/markdown.py`, `output/sarif.py`, code and config fixtures and tests, `tests/conftest.py`, `frontend/src/pages/CodeConfig.tsx`, `frontend/src/pages/code-config/`, code golden rows. File extensions `.py`, `.java`, `.go`, and (P2) `.pem`, `.crt`, `.cer`, `.der`, `.key`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `*.pub` | `M3toAll` 1, `M2M3-01` |
| M4 | `scanners/cloud/**`, `kb/cloud_registry.yaml`, `output/cyclonedx.py`, `api/**`, `frontend/**` except M3's page, `Dockerfile`, `.dockerignore`, root `README.md`, `scripts/demo.sh`, cloud fixtures, `scan_result_sample.json`, cloud, output and API tests, cloud golden rows, deck and recording | `M4toAll` 1, `M3M4-01` |

Nobody edits another member's files. A needed change is a new item in the pair file.

## 2. Process

- Communications and shared plan updates go directly to `main`, after reconciling with `origin/main` (`docs/PLAN.md` section 11, `M1M4-14`).
- Implementation stays on member branches: M1 on the persistent `m1` branch, M2 on `m2/<topic>`, M3 on `m3/code-engine`, M4 on `m4/<topic>` (`M1C-04` replies).
- Implementation reaches `main` at milestones, through M1 or the user: core engine (tasks 1.3 to 1.8), runnable CLI and native reports (1.9, 1.11, 1.10), evaluation and starter integration (1.12). No force pushes (`docs/PLAN.md` section 11).
- A task done on a member branch and its integration on `main` are recorded separately (`M3C-03`, M1).
- `docs/DECISIONS.md` is local-only and Git-ignored. Settled items live in reply rows, in the toAll files and in `docs/PLAN.md`. README rule 5 is superseded (`README.md`).
- A task is reported done only after its tests and lint pass.
- No network in tests. The starter kit is read-only.

## 3. Contract

- `models.py` and `scanners/base.py` are frozen. Any field change needs AGREED from all four members (`README.md` rule 6).
- Scanners yield only `Finding` or `ScanError`. They assign no tier, threat, score, `pq_status` or verdict. Only the engine does.
- The engine retains every original `Finding` with all its extra keys. Consumers read raw facts from `ScanResult.findings` through each asset's `finding_ids` (`docs/PLAN.md` section 6).
- M1 builds every `TLSSession` from the findings sharing a `session_id`, in task 1.9. M2 never instantiates `TLSSession` (`M1M2-01`).
- Network findings use the hex codepoint as `raw_name`, and `kind_hint` selects the namespace. `TLSSession` fields carry the verified registry IANA name. An unknown code keeps its hex spelling. Raw `extra["session"]` keeps hex values in client order. SSH keeps its wire names (`M1M2-01`, `M1M2-02`, `M1M2-04`).
- A SAFE hybrid key exchange with unobservable authentication has overall verdict UNKNOWN, unless an observed component is CRITICAL or MEDIUM (`docs/PLAN.md` sections 6 and 7.1). When a certificate is observed, for example with a keylog, authentication is classified normally (`M2M4-06`).
- `negotiated` is true only for a selection seen in the ServerHello, or for SSH under the RFC 4253 first-match rule. Client offers alone are false. Configured policies and config settings are never labelled negotiated (`M1M2-03`, `M1M4-03`, `M1M3-09`).
- Plaintext findings and hygiene-only warnings are shown and are excluded from the quantum score and readiness (`docs/PLAN.md` section 7.5, `M1M3-04`).
- `ScanResult.roadmap` is a list of `RoadmapItem(phase 0 to 3, action, asset_ids, occurrence_count)`. Native reports are valid `ScanResult` documents with no extra top-level block (`models.py`).
- Engine asset values use the CycloneDX 1.6 `primitive` and `mode` lists, lowercase `mode` or None, and stable unique `asset_id` values. Raw `Finding.mode` may be uppercase (`M1M4-08`).
- No private key material anywhere. Hard-coded key literals are `<redacted>` in `snippet`, and no key bytes go in `extra` (`M3M4-06`, `M1M3-02`).
- Unverified facts carry `verify` and are checked against the primary source. No invented codepoints, OIDs or standard numbers. A verify-only registry row cannot pass a golden gate (`M2C-01`).
- Output is sorted and deterministic. Ids come from `finding_id`.
- An unsupported input yields a `ScanError`, never an empty success. Key and config files are reported as unsupported coverage until M3's P2 scanners exist (`M1M2-03`, `M3C-01`).

## 4. Evidence keys in `Finding.extra`

| Owner | Keys | Source |
|---|---|---|
| Frozen | `origin`, `state`, `public_exposure`, `source_timestamp`, `hygiene_only`, `hygiene_flags`, `authentication_observable`, `session` | `docs/PLAN.md` section 6 |
| M2 and M3 | `codepoint`, `iana_name` (None when not verified) | `M1M2-02`, `M1M3-09` |
| M2 | `certificate_state` (`observed`, `encrypted`, `absent`), `http` (method, path, host, server) | `M2M4-02`, `M2M4-03` |
| M3 | `rule`, `key_size_source`, `unresolved`, `resolved_from_line`, `hand_rolled`, `mode_source` | `M3toAll` 4 |
| M4, KMS | `alias`, `key_usage`, `rotation_status`, `valid_to`, `deletion_date`, `multi_region` | `M1M4-01` |
| M4, listener | `lb_name`, `lb_type`, `listener_protocol`, `port`, `ssl_policy`, `listener_arn`, `certificate_arns`, `redirects_to_https` | `M1M4-01` |
| M4, certificate | `domain`, `cert_status`, `not_before`, `not_after`, `in_use_by`, `signature_algorithm`, `key_algorithm` | `M1M4-01` |

- `hygiene_flags` values: `insecure_rng`, `hardcoded_key` (M3); `rotation_disabled`, `multi_region_key`, `redirect_only_listener` (M4).
- `key_size_source` values: `literal`, `constant`, `param_default`, `lookahead`, `flow`, `ambiguous`, `unresolved`. `flow` replaces `file_scope` (`M1M3-01`).
- `mode_source` value: `block_loop`. `jca_default` and `provider_assumed` are withdrawn (`M1M3-06`).
- A member announces a change to any of their keys before making it.

## 5. Settled facts per area

### Network (M2)
- The kit gives 97 TLS sessions, 24 SSH sessions and 14 HTTP flows, from both tshark and `purepy.py` (`M2M4-05`).
- The whole kit has `authentication_observable` false, because no Certificate message is in the capture (`M2M4-02`).
- Plaintext HTTP is a `PLAINTEXT` finding with `hygiene_only` true, never a session (`M2M4-03`).
- `kb/tls_registry.yaml` is keyed by hex string, with `iana` and an `openssl` alias list per entry. It holds no tier (`M2M4-04`).
- The live probe is optional P2, behind `--probe host:port`. Nothing touches the network without it (`M1M2-05`).

M1 consumption follow-up, user-relayed 2026-10-10 (M1M2-06; M2 confirmation
and tested commit review pending):

- ClientHello-only session_id groups can lack a session finding/extra.session while retaining offers and ScanError. ServerHello-only groups may have null offered_* values. Missing metadata is incompleteness, not conflicting evidence.
- HelloRetryRequest alone establishes no negotiated selection; its session finding is negotiated=false.
- Protocol-version findings keep labels and optional version codepoints, resolved only through versions. M1 dispatches by kind_hint; namespace-specific pcap.tls.* detectors avoid ID collisions.
- TLS 1.2 ECDHE groups use ServerKeyExchange evidence frames.
- Session IDs depend on scan-root-relative file paths. Golden evaluation fixes the repository root and portable rows avoid literal session_id selectors; ambiguous matches fail.

### Code (M3)
- A size passes from a key generation to a consumer only through a demonstrated same-file flow link. Otherwise `key_size` is None, `unresolved`, confidence at most 0.5 (`M1M3-01`).
- Bare Java `AES` leaves `mode` None. Go ECB needs affirmative `block_loop` evidence. Explicit transform strings set `mode` directly (`M1M3-06`).
- The hard-coded key warning fires only when a literal reaches an AES key sink. The three HMAC decoy files are outside the rule (`M1M3-02`).
- AES with an undeterminable size is MEDIUM with the rationale "key size not determinable" (`M1M3-07`).
- Decoys: findings exist for AES-256-GCM, SHA-384, HMAC-SHA256 and PBKDF2 and come out SAFE. `SecureRandom`, `os.urandom` and `crypto/rand` emit no finding (`M3M4-03`).
- The scanner takes one file per call. Exclusions and path order come from M1's pipeline (`M3M4-07`).

### Cloud, CBOM, API and UI (M4)
- One `KEY` finding per KMS key. `resource_id` is `KeyArn`, then `KeyId`, then `AliasName`. The alias is in `extra.alias` (`M1M4-05`, `M1M4-07`).
- Two `PLAINTEXT` hygiene findings for the HTTP:80 listeners. `public-web-alb` is redirect-only. `batch-internal-alb` forwards HTTP (`M1M4-06`).
- `source_timestamp` is the dump's `GeneratedAt`. M4 computes no expiry and no warning. The engine derives them into asset `rationale` and `recommendations` (`M1M4-02`).
- The engine joins listener to certificate through `Location.resource_id` and `extra.certificate_arns` (`M1M4-03`).
- `multi_region_key` and HSM backing are context, not automatically weaknesses. The UI shows them as context (`M1M4-02`).
- M4 builds one `related-crypto-material` CBOM component per KMS key, referencing the classified algorithm, without scoring it again (`M1M4-05`).
- Code findings enter the CBOM as evidence occurrences. Test-code occurrences carry `quantumtrace:testCodeOnly = true`. Library findings become `library` components. Hygiene-only findings are not CBOM components (`M3M4-05`).
- Strict validation uses `cyclonedx-python-lib[json-validation]>=8`, present in `pyproject.toml` (`M1M4-12`).
- `/api/scoring` serves `kb/scoring.yaml` read-only and returns an unavailable response when it is missing. `/api/report.md` returns a not generated yet response until `M3D-08` exists (`M1M4-09`, `M3M4-04`).
- The Network page shows `pq_status` and `verdict_tier` as separate columns, and authentication from `certificate_state` (`M4toAll` 4).
- Roadmap phases are planning phases, not regulatory deadlines: 0 this week, 1 now, 2 by 2027, 3 by 2030 (`M1M4-10`).
- The Docker image installs `tshark` with `DEBIAN_FRONTEND=noninteractive`. `openssl` is needed only for `--probe` (`M2M4-05`).
- Frontend types come from `/openapi.json`. Nobody hand-writes `ScanResult` (`M3M4-01`).

### Golden data (all)
- Format: `docs/GOLDEN.md` and `docs/golden.schema.json`. Rows go in `tests/golden/expected.yaml`. Each owner writes their own rows with a tested branch commit reference (`M1N-04`, `M1M4-13`).
- M2: session rows, count rows for 97, 24 and 14, finding rows for fixtures (`M2D-09`). M3: the 24 kit files with the corrections of `M1M3-08` (`M3D-11`). M4: 10 key resources, 7 listener resources, 5 certificate resources (`M4D-10`).

## 6. Dependencies between members

Each member's own delivery order is section 2 of their toAll file. Only these cross-member dependencies are stated there:

| Delivery | Waits for | Source |
|---|---|---|
| M3's Code & Config page (`M3D-09`) | M4's sample and scaffold (`M4D-01`, `M4D-03`) | `M3N-02`, `M3N-03` |
| M4's Network page on real data | M2's five sample files (`M2D-02`) | `M4N-04` |
| M4's ELB policy table and CBOM suite identifiers | M2's registry (`M2D-03`) | `M4N-05` |
| M4's demo step with `refuse.lab` | M2's fixture pcaps (`M2D-06`) | `M4N-06` |
| M4's `/api/report.md` content | M3's Markdown writer (`M3D-08`, after `M3D-04`) | `M4N-08` |
| M4's `/api/scoring` content | M1's `kb/scoring.yaml` (task 1.3) | `M1M4-09` |
| M2's image-based runs | M4's image with `tshark` (`M4D-11`) | `M2N-06` |
| M3's P2 config and key-file scanners (`M3D-12`) | M2's registry and `describe_certificate` (`M2D-03`, `M2D-07`) | `M3N-04` |
| M1's pipeline and integration | Registered adapters from M2, M3 and M4 | `M1N-01`, `M1N-02`, `M1N-03` |
| M1's evaluation | Golden rows from M2, M3 and M4 | `M1N-04` |

## 7. Older text that a later row overrides

These lines still appear in the files. The later row is the agreement.

| Older text | Overridden by |
|---|---|
| `M1M4-07` ask: "KMS keys have no ARN in the data" | `M1M4-07` reply: the data has `KeyArn` |
| `M1M4-14` first M1 row: M4 never pushes to `main` | `M1M4-14` second M1 row: communications go directly to `main` |
| `M1M3-01` ask and first rows: `key_size_source = file_scope` | Last `M1M3-01` rows: `flow`, with a demonstrated link |
| `M1M3-06` first M3 row: bare Java `AES` gives ECB with `jca_default` | Last `M1M3-06` rows: `mode` None |
| `M2M4-04` first row: groups from `openssl list -tls-groups` | Second row: `-all-tls-groups`, plus `prime256v1` marked `verify` |
| `M3D-05` and `M3M4-06`: "held until `M1M3-02` is settled" | `M1M3-02` is AGREED. When `M3D-05` ships is M3's call |
| README rule 5: log settled items in `docs/DECISIONS.md` | README "User workflow update" and "Final status" |
| `Status: OPEN` inside a toAll file | README index: FINAL |

## 8. Work still to do

These are tasks, not open agreement items.

- M3: `ruff format` on `scanners/code/engine.py` and `tests/test_code_engine.py`, and the flow-link change of `M1M3-01`, before `m3/code-engine` is integrated.
- M2: the tested commit hash for `purepy.py`, once `m2/purepy-reader` is pushed (`M2C-01`).
- M4: verify the Docker base image tag, the AWS ELB policy tables and the meaning of `SYMMETRIC_DEFAULT` against the primary source.
- All: every item marked `verify`.

## 9. After this file

This file is final. A promise that changes later is a new item with a new ID in the pair file, and this file is corrected in the same commit.
