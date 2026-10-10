# M3 to all

Status: OPEN

From M3. Rules: `README.md`. Same four sections and checklist format as `M4toAll.md`.

Note on hours: by the user's instruction hour values are ignored for now. `By` and `Hour` fields read `n/a`. Order of delivery is stated as dependencies instead.

## 1. Owns

- `src/quantumtrace/scanners/code/**` (engine, `rules/python.yaml`, `rules/java.yaml`, `rules/go.yaml`, `python_ast.py`, `manifests.py`)
- `src/quantumtrace/scanners/config/**`
- `src/quantumtrace/output/markdown.py`, `src/quantumtrace/output/sarif.py`
- `tests/fixtures/code/**`, `tests/fixtures/config/**`, `tests/test_code_*.py`, `tests/test_config_*.py`
- `tests/conftest.py` (a minimal `sys.path` helper; M1 may replace it)
- Frontend: `frontend/src/pages/CodeConfig.tsx` and `frontend/src/pages/code-config/` only

## 2. Delivers

| ID | To | What | By |
|---|---|---|---|
| M3D-01 | M1 | `CodeScanner` (name `code.regex`, source type `code`), registered with `@register`, handles `.py`, `.java`, `.go`, one file per call. Rule engine with comment masking, file-scope constants, parameter defaults, key-size and iteration resolution, same-file flow links. DONE, on main | done |
| M3D-02 | M1 | `rules/python.yaml` and `rules/java.yaml` with a fixture and a test per rule asserting `raw_name`, line and `key_size` | done |
| M3D-03 | M1 | `rules/go.yaml`, import-only findings (confidence 0.6) deduped against call findings, SAFE-decoy negative tests | done |
| M3D-04 | M1 | Test that scans `sample-repos/` and diffs the result against Appendix D.4 (line tolerance 2) | done |
| M3D-05 | M1, M4 | Hygiene-only findings for insecure RNG (`hygiene_flags` `insecure_rng`) and hard-coded AES key (`hygiene_flags` `hardcoded_key`, literal redacted in `snippet`). `M1M3-02` is settled | done |
| M3D-06 | M1, M4 | `extra["resolved_from_line"]` (int) on findings whose size or transform came from a constant or parameter default | done |
| M3D-07 | M1, M4 | `manifests.py`: `library` findings from `requirements*.txt`, `pom.xml`, `go.mod`, detector `code.<language>.manifest`, `raw_name` `name==version` for an exact pin and `name` otherwise, Maven names `groupId:artifactId`. DONE | done |
| M3D-08 | M4 | `render_markdown_summary(result) -> str` and `write_markdown_summary(result, path)`, sorted and deterministic (P1) | done |
| M3D-09 | M4 | `frontend/src/pages/CodeConfig.tsx`: findings grouped by file, one row per finding (the asset with the worst tier is shown), snippet and line, tier badge, recommendation, filters. DONE, on main; run in a headless browser against the real kit result (the Test code filter and the error state were not exercised) | done |
| M3D-10 | All | `python_ast.py` alias resolution (DONE). `output/sarif.py` (P2, only if everything above is green) | later |
| M3D-11 | M1 | Code golden rows in `docs/GOLDEN.md` format for the 24 kit files (asset rows with line and tier, finding rows for hygiene flags, count rows), with the D.4 corrections of `M1M3-08`. Written to the code section of `tests/golden/expected.yaml` (confirmed by M1 in `M3C-01`) | done |
| M3D-12 | M1, M2 | `scanners/config/keyfiles.py` and `webserver.py` (P2). Owns `.pem`, `.crt`, `.cer`, `.der`, `.key` and SSH key files `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `*.pub` (`M2M3-01`, agreed). Until they exist M1 reports key and config files as unsupported coverage, not as a successful scan | later |

## 3. Needs

| ID | From | What | By |
|---|---|---|---|
| M3N-01 | M1 | Items `M1M3-01` to `M1M3-10` settled (all replied; `M1M3-01` and `M1M3-06` CHANGED and accepted). Later conventions agreed by relay and recorded in Section 4 below: usage consistency, local key assignment, iterations, raw names, TLS versions | done |
| M3N-02 | M4 | `scan_result_sample.json` with the code cases listed in the reply to `M3M4-02` (`M4D-01`) | before M3D-09 |
| M3N-03 | M4 | Scaffold, generated TS types, `useScanResult()`, `TierBadge`, sortable table, empty Code & Config route (`M4D-03`) | before M3D-09 |
| M3N-04 | M2 | P2 only: `kb/tls_registry.yaml` with `load_registry()` (`M2D-03`) and `describe_certificate` in `certs.py` (`M2D-07`, `M2M3-02`). Nothing for the code scanner | before M3D-12 |
| M3N-05 | M1 | Answered by `M1M3-09`: config findings keep `raw_name`, carry verified `codepoint` and `iana_name`, and set `kind_hint` `cipher_suite` or `group`; tasks 1.3 to 1.5 resolve them (P2) | before M3D-12 |

## 4. Promises

- M3 scanners only detect. They never assign tier, threat, score, pq_status or verdict.
- M3 imports models and helpers from `quantumtrace.models` and `quantumtrace.scanners.base`. It uses `finding_id` for identity, `is_test_path` for `in_test_code` and `@register` for the adapter. It never redefines or shadows them.
- M3 adds no field to `Finding` or `CryptoAsset`. Extra data goes in `Finding.extra`. Keys M3 sets: `rule`, `key_size_source`, `unresolved`, `resolved_from_line`, `hand_rolled`, `hygiene_only`, `hygiene_flags`, `mode_source`, `usage_source`, `iterations`, `parameter_source`, `source_constant`. P2 only: `codepoint`, `iana_name`.
- `hygiene_flags` values: `insecure_rng`, `hardcoded_key`, `tls_verify_disabled`.
- `key_size_source` is one of `literal`, `constant`, `param_default`, `lookahead`, `flow`, `ambiguous`, `unresolved`. `flow` is emitted (`M1M3-01`), and also for a literal key assigned to a local name in the same function (`resolved_from_line` is the assignment line).
- `usage_source`: the only value is `flow`; set on an RSA generation upgraded to `signature` by a complete same-file sink check (`M1M3-10`). Java Ed25519, Ed448 and EdDSA generation carry usage `signature` directly.
- `iterations` (int): the PBKDF2 work factor, only when literal, a constant or a parameter default (one call-site hop); nothing when unresolved; never part of asset identity. Python `hashlib.pbkdf2_hmac`, `PBKDF2HMAC` and PyCryptodome `PBKDF2`, Java `PBEKeySpec`, Go `pbkdf2.Key`. `hashlib.scrypt` has raw_name `scrypt`, usage `kdf`, no parameters.
- `parameter_source`: the only value is `library_default`; set when an emitted hash or count comes from a documented library default (PyCryptodome `HMAC.new` without `digestmod` is HMAC-MD5; PBKDF2 without `prf` is HMAC-SHA1 with iterations 1000); confidence at most 0.8.
- `source_constant` (string): the constant as written for a configured TLS version (`ssl.PROTOCOL_TLSv1`, `tls.VersionTLS10`, the `getInstance` protocol string). The finding's `raw_name` is one spelling for all languages: `TLS 1.0`, `TLS 1.1`, `SSLv3`, `kind_hint` `protocol_version`.
- Confidence: rule value by default. 0.8 maximum when the size came from `lookahead` or `flow`, for a hand-rolled PBKDF2, for a hard-coded key found through a local assignment and for a library default. 0.5 maximum when the size is `ambiguous` or `unresolved`, or an identifier could not be resolved. 0.6 for import-only findings.
- Size inheritance (`M1M3-01`, agreed): RSA and AES sizes pass from a generation to a consumer only through a demonstrated same-file flow link (producer function, binding variable, consumer call) that resolves the actual argument or parameter identity and scope. Unrelated calls, reassigned or conflicting bindings and distinct keys of the same size never link. Unknown stays None, `unresolved`, confidence at most 0.5. Directly observed constant, literal or default provenance is kept.
- Scope (from M4's probe): the scanner reads `.py`, `.java` and `.go` only. Python `random.random()` and `random` calls other than `getrandbits` and `randbytes` are not flagged. Go `math/rand` calls are flagged only when `crypto/rand` is not imported in the same file. JavaScript and web server configuration files are not scanned (P2, `M3D-12`).
- Legacy settings detected in code: TLS 1.0, TLS 1.1 and SSLv3 in Python (`ssl.PROTOCOL_TLSv1`, `_TLSv1_1`, `_SSLv3`, `ssl.TLSVersion.TLSv1`, `TLSv1_1`, `SSLv3`), Java (`SSLContext.getInstance` with the literal or a file-scope constant) and Go (`MinVersion` or `MaxVersion` set to `tls.VersionTLS10`, `VersionTLS11`, `VersionSSL30`); Go `crypto/des` and `crypto/rc4` (raw names `DES`, `TripleDES`, `RC4`); Go `InsecureSkipVerify` with the literal `true` (hygiene-only, flag `tls_verify_disabled`). Constants that disable a version (`ssl.OP_NO_TLSv1`) emit nothing. The tier, the classically-broken marking, the advice and the exclusion from scoring are M1's (`classify.py`).
- Known limits, not claimed as coverage: a Python string literal such as `"ssl.PROTOCOL_TLSv1"` is matched (strings are not masked for call patterns); Java `setEnabledProtocols` and `jdk.tls.disabledAlgorithms`, and verification disabled outside Go (`verify=False`, `check_hostname=False`, Java trust-all managers), are not covered; Go `MaxVersion` set to a legacy version is flagged like `MinVersion`.
- Mode inference (`M1M3-06`, M1 version): bare Java `AES` leaves `mode` None, because the active provider is not verified from one file. `mode` is set only from an explicit transform string, or, for Go, `mode_source=block_loop` with ECB when the code shows each plaintext block encrypted independently with no XOR, IV or previous-block state. Otherwise `mode` is None. Confidence at most 0.8. Negative cases (custom provider, manual chaining) get tests.
- Config findings (P2, `M1M3-09`, M1 version): `raw_name` exactly as observed, `kind_hint` `cipher_suite` for suites and `group` for groups and curve aliases, and `extra["codepoint"]` and `extra["iana_name"]` only when verified, `None` otherwise. Config settings are never labelled negotiated. Names the registry does not resolve stay `None`; M3 does not rely on the registry for X9.62 names other than those M2 lists (`M2M3-03`).
- Detector names have the form `code.<language>.regex:<RULE_ID>` for scanner rules and `code.<language>.manifest` for manifests.
- Output of one file is sorted by line, rule id and raw name. Ids are hash based and stable.
- `Location.file` is relative to the scan root, in posix form. `snippet` is at most 200 characters.
- M3 never prints or stores key material. Every string literal in `snippet` is replaced by `<redacted>` unless it equals a value a literal group of the rule captured (algorithm, transform, name); key groups are never visible, and no key bytes go into `extra`.
- The scanner needs no external binary and no network. It skips files over 5 MB with a `ScanError`.
- The scanner takes one file per call. Directory walking and `ScanOptions.exclude_dirs` are applied by M1's pipeline.
- Anything unverified is marked `# verify`. No invented codepoints, OIDs or standard numbers.
- M3 reports a task done only after its tests and lint pass.
- M3 announces a change to any `extra` key before making it.
- M3 never edits another member's files. Changes to those go in an agreement item.
- Kit on main (informational, `sample-repos`): 56 findings and 16 assets, 13 non-wrapper plus 3 wrappers (hard-coded symmetric key, INSECURE-RNG, library). RSA-1024 is 2 assets (key-generation sites with padding unknown; sign and verify sites with PKCS1v15), SHA-1 is 2 (hash, signature), SHA1withRSA is the only multi-part composite, PBKDF2 is 2 (hand-rolled, library). Hygiene-only, library and plaintext assets stay in `result.assets` as UNKNOWN warnings and are not CBOM components.
- M3's changes reach the repository through the user's own commits.

## 5. Confirmation checklist

Reply with a row in the table below, using the checklist ID.

| ID | Statement | Reply from |
|---|---|---|
| M3C-01 | Section 2 rows to M1 and Section 3 rows from M1 are correct | M1 |
| M3C-02 | Section 2 rows to M4 and Section 3 rows from M4 are correct | M4 |
| M3C-03 | Section 4 is acceptable | M1, M2, M4 |

When all rows have AGREED or CHANGED from every named member, M3 sets `Status: ALIGNED` at the top.

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M3C-01 | M1 | n/a | CHANGED | Deliverables and dependencies accepted with M1M3 replies, milestone branch policy and docs/GOLDEN.md format. M3D-01 is reported locally done; M1 has not received its implementation/tested commit, so please publish that evidence rather than treating it as integrated. |
| M3C-03 | M1 | n/a | CHANGED | Promises accepted with bounded evidence inference in M1M3-01/06, redaction and no engine guessing. Frozen contracts unchanged. Per user update, tested branch publication and main milestone integration are tracked separately. |
| M3C-03 | M2 | n/a | AGREED | Section 4 is acceptable. M2 reads `M3N-04` as "nothing needed from M2"; the three items in `M2M3agreement.md` are asks from M2 to M3 and stay OPEN until M3 replies. Neither side blocks on them: both have a fallback. |
| M3C-01 | M1 | n/a | CHANGED | Publication evidence now received: origin/m3/code-engine at dc1493e. M1 reproduced 95 offline tests passing (35 code-engine plus 60 foundation/contracts), and Ruff lint passes. Ruff format --check fails for src/quantumtrace/scanners/code/engine.py and tests/test_code_engine.py using the branch pyproject.toml. Please format those owned files and address the key-flow issue in the latest M1M3-01 reply before integration. Language rule YAMLs are not in this snapshot; starter coverage is not yet verified. This supersedes the earlier missing-publication note, not the remaining integration gates. Communications go directly to main; M3 implementation remains on its member branch. |
| M3C-01 | M1 | n/a | CHANGED | Updated schedule accepted: code golden rows go in tests/golden/expected.yaml after M3D-04 using docs/GOLDEN.md/schema; config/keyfile adapters M3D-12 remain P2, outside the H6 code-scanner requirement. Until available, coverage must be reported as unsupported rather than claiming a successful scan of key/config files. Markdown follows M3D-04. M1M3-09 is answered; flow inference and format fixes remain pending on dc1493e before integration. |
| M3C-03 | M1 | n/a | CHANGED | Accept flow provenance and announced extra keys, with namespace-qualified config mapping in M1M3-09 and affirmative mode evidence in the latest M1M3-06 reply. A missing provider declaration or chaining-library call does not establish provider/default mode or independent encryption. Frozen contracts unchanged; preserve raw evidence and explicit uncertainty. |
| M3C-02 | M4 | n/a | CHANGED | M3N-02 and M3N-03 are correct. M4's sample contains the code cases listed in the M3M4-02 reply, which is more than the 8 assets M4 first promised: RSA-1024 in three languages, MD5, SHA-1, Ed25519, AES-128-ECB with hard-coded key, AES-256-GCM, SHA-384, HMAC-SHA256, PBKDF2, three insecure-RNG warnings, a hard-coded key warning, one test-path-only asset and one library finding. M3D-08 has no hour, so /api/report.md returns a clear "not generated yet" response until it exists. |
| M3C-03 | M4 | n/a | AGREED | Section 4 is acceptable. |
