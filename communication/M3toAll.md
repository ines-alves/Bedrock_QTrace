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
| M3D-01 | M1 | `CodeScanner` (name `code.regex`, source type `code`), registered with `@register`, handles `.py`, `.java`, `.go`, one file per call. Rule engine with comment masking, file-scope constants, Python parameter defaults, key-size resolution. DONE, 35 tests. Published on `m3/code-engine` (commit `dc1493e`). Open before integration: `ruff format` on the two owned files and the flow-based size inheritance of `M1M3-01` | done |
| M3D-02 | M1 | `rules/python.yaml` and `rules/java.yaml` with a fixture and a test per rule asserting `raw_name`, line and `key_size` | after M3D-01 |
| M3D-03 | M1 | `rules/go.yaml`, import-only findings (confidence 0.6) deduped against call findings, SAFE-decoy negative tests | after M3D-02 |
| M3D-04 | M1 | Test that scans `sample-repos/` and diffs the result against Appendix D.4 (line tolerance 2) | after M3D-03 |
| M3D-05 | M1, M4 | Hygiene-only findings for insecure RNG (`hygiene_flags` `insecure_rng`) and hard-coded AES key (`hygiene_flags` `hardcoded_key`, literal redacted in `snippet`). Held until `M1M3-02` is settled | after M3D-03 |
| M3D-06 | M1, M4 | `extra["resolved_from_line"]` (int) on findings whose size or transform came from a constant or parameter default | after M3D-02 |
| M3D-07 | M1, M4 | `manifests.py`: `library` findings from `requirements.txt`, `pom.xml`, `go.mod` (P1) | after M3D-03 |
| M3D-08 | M4 | `render_markdown_summary(result) -> str` and `write_markdown_summary(result, path)`, sorted and deterministic (P1) | after M3D-04 |
| M3D-09 | M4 | `frontend/src/pages/CodeConfig.tsx`: findings grouped by file, snippet and line, tier badge, recommendation, filters (P1) | after M4D-03 |
| M3D-10 | All | `python_ast.py` alias resolution (P1); `output/sarif.py` (P2, only if everything above is green) | later |
| M3D-11 | M1 | Code golden rows in `docs/GOLDEN.md` format for the 24 kit files (asset rows with line and tier, finding rows for hygiene flags, count rows), with the D.4 corrections of `M1M3-08`. Location in `tests/golden/expected.yaml` to be confirmed by M1 | after M3D-04 |
| M3D-12 | M1, M2 | `scanners/config/keyfiles.py` and `webserver.py` (P2). Owns `.pem`, `.crt`, `.cer`, `.der`, `.key` and SSH key files (`M2M3-01`). Until they exist such files yield no findings | later |

## 3. Needs

| ID | From | What | By |
|---|---|---|---|
| M3N-01 | M1 | Items `M1M3-01` to `M1M3-08` settled (all replied; `M1M3-01` and `M1M3-06` CHANGED and accepted) (RSA size inheritance, hard-coded key scope, raw name mapping, hygiene representation, hand-rolled PBKDF2, ECB representation, unknown key size, golden corrections) | before M3D-03 |
| M3N-02 | M4 | `scan_result_sample.json` with the code cases listed in the reply to `M3M4-02` (`M4D-01`) | before M3D-09 |
| M3N-03 | M4 | Scaffold, generated TS types, `useScanResult()`, `TierBadge`, sortable table, empty Code & Config route (`M4D-03`) | before M3D-09 |
| M3N-04 | M2 | P2 only: `kb/tls_registry.yaml` with `load_registry()` (`M2D-03`) and `describe_certificate` in `certs.py` (`M2D-07`, `M2M3-02`). Nothing for the code scanner | before M3D-12 |
| M3N-05 | M1 | `M1M3-09`: resolve config findings that carry `extra["codepoint"]` (P2) | before M3D-12 |

## 4. Promises

- M3 scanners only detect. They never assign tier, threat, score, pq_status or verdict.
- M3 imports models and helpers from `quantumtrace.models` and `quantumtrace.scanners.base`. It uses `finding_id` for identity, `is_test_path` for `in_test_code` and `@register` for the adapter. It never redefines or shadows them.
- M3 adds no field to `Finding` or `CryptoAsset`. Extra data goes in `Finding.extra`. Keys M3 uses: `rule`, `key_size_source`, `unresolved`, `resolved_from_line`, `hand_rolled`, `hygiene_only`, `hygiene_flags`, `mode_source`, `provider_assumed`, `codepoint`, `iana_name`.
- `key_size_source` is one of `literal`, `constant`, `param_default`, `lookahead`, `flow`, `ambiguous`, `unresolved`. (`file_scope` is retired by `M1M3-01`; `flow` is not emitted until the engine change lands.)
- Confidence: rule value by default. 0.8 maximum when the size came from `lookahead` or `flow`. 0.5 maximum when the size is `ambiguous` or `unresolved`, or an identifier could not be resolved. 0.6 for import-only findings.
- Size inheritance (`M1M3-01`): RSA and AES sizes pass from a generation to a consumer only through a same-file flow link (producer function, binding variable, consumer call). Unlinked, imported or unused allocations stay None, `unresolved`, confidence at most 0.5.
- Mode inference (`M1M3-06`): bare Java `AES` gives `mode=ECB`, `mode_source=jca_default`, `provider_assumed=SunJCE` only when the file names no provider; a Go `block.Encrypt` loop with no chaining mode gives ECB, `mode_source=block_loop`. Confidence at most 0.8.
- Config findings (P2) keep `raw_name` as seen and carry `extra["codepoint"]` and `extra["iana_name"]`, `None` when unresolved (`M2M3-03`).
- Detector names have the form `code.<language>.regex:<RULE_ID>`.
- Output of one file is sorted by line, rule id and raw name. Ids are hash based and stable.
- `Location.file` is relative to the scan root, in posix form. `snippet` is at most 200 characters.
- M3 never prints or stores key material. Hard-coded key literals are replaced by `<redacted>` in `snippet`, and no key bytes go into `extra`.
- The scanner needs no external binary and no network. It skips files over 5 MB with a `ScanError`.
- The scanner takes one file per call. Directory walking and `ScanOptions.exclude_dirs` are applied by M1's pipeline.
- Anything unverified is marked `# verify`. No invented codepoints, OIDs or standard numbers.
- M3 reports a task done only after its tests and lint pass.
- M3 announces a change to any `extra` key before making it.
- M3 never edits another member's files. Changes to those go in an agreement item.
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
