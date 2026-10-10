# M3M4 agreement

Status: FINAL

Final on 2026-10-10. The Final decisions table below is the agreed outcome. The Items keep the original asks so the replies stay readable. Where an ask and its reply differ, the reply wins. A reply row also wins over the Final decisions table, which is M4's summary of the replies.

Between M3 (code scanner, markdown summary, Code & Config page) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

M4 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/PLAN.md` section 6 as correct. M4 does not ask for changes to it. (`docs/DECISIONS.md` is local-only, so the sources below cite shared files.)

## Already decided by M1, adopted by M4 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `CryptoAsset` or `Finding`. Any change needs all four members. | `models.py`, `docs/PLAN.md` section 6 |
| Per-finding data | `Finding` already has `language` and `in_test_code`. The engine keeps every original `Finding`. M4 reads them through each asset's `finding_ids`. | `models.py`, `docs/PLAN.md` section 6 |
| Warnings | A warning that is not a cryptographic primitive uses `extra["hygiene_only"]` true and `extra["hygiene_flags"]` (list of strings). Hygiene-only warnings are excluded from the quantum score and readiness. | `docs/PLAN.md` sections 6 and 7.5 |
| Scanners supply facts | Scanners report what they see. The engine assigns tier and verdict. | `docs/PLAN.md` section 6 |
| Scan options | Default excluded directories: `.git`, `node_modules`, `venv`, `.venv`, `vendor`, `out`, `agents`. | `models.py` |
| Markdown owner | M3 owns `output/markdown.py` and `write_markdown_summary`. | `docs/PLAN.md` section 6 |

## Final decisions

| ID | Final decision |
|---|---|
| M3M4-01 | As asked. M3 touches only `src/pages/CodeConfig.tsx` and `src/pages/code-config/`. No npm dependency without telling M4. Nobody hand-writes the `ScanResult` type. |
| M3M4-02 | The sample contains: RSA-1024 signature in Python, Java and Go (each file also uses SHA-1), MD5, SHA-1 checksum, Ed25519, AES-128-ECB with hard-coded key, AES-256-GCM, SHA-384, HMAC-SHA256, PBKDF2; hygiene-only insecure RNG in Python, Java and Go and one hard-coded AES key; one asset whose occurrences are all in a test path; one library finding `cryptography==46.0.5`. File paths come from `sample-repos`. |
| M3M4-03 | Language is `Finding.language`, test flag is `Finding.in_test_code`, hygiene flags are `insecure_rng` and `hardcoded_key`, ECB is `mode`. M3 emits findings for AES-256-GCM, SHA-384, HMAC-SHA256 and PBKDF2 and the engine assigns SAFE. `SecureRandom`, `os.urandom` and `crypto/rand` emit no finding, so no asset exists for them. |
| M3M4-04 | `render_markdown_summary(result) -> str` and `write_markdown_summary(result, path)`, sorted and deterministic, delivered after M3D-04 with no hour. Until then `/api/report.md` returns a not generated yet response. |
| M3M4-05 | As asked. `extra["resolved_from_line"]` is an int. Library findings use `kind_hint` `library` and `raw_name` `name==version`. Hygiene-only findings stay off the CBOM. |
| M3M4-06 | As asked. The redaction ships with the hard-coded key rule. No key bytes in `extra`. |
| M3M4-07 | No external binaries. The scanner takes one file per call, so `ScanOptions.exclude_dirs` and path order are applied by M1's pipeline. Within one file findings are sorted by line, rule id and raw name. |

## Items

### M3M4-01 | By H2
Ask: frontend ownership is split as follows.
- M4: `frontend/` scaffold and config, `src/api/`, `src/components/`, every page except Code & Config.
- M3: `src/pages/CodeConfig.tsx` and `src/pages/code-config/`.
- Nobody adds an npm dependency without telling the other. Nobody hand-writes the `ScanResult` type.
Why: one lockfile, one Docker build, no collisions.
Preference: as stated.
Fallback: M3 builds the page in a separate folder and M4 integrates it.

### M3M4-02 | By H2
Ask: M3 lists what `scan_result_sample.json` must contain for the Code & Config page (files, languages, tiers, warnings, test-code cases).
Why: M3 builds on the sample until H6. M4 delivers the scaffold at H3 (see `M4toAll.md`).
Preference: as stated.
Fallback: M4 includes 8 code assets across Python, Java, Go, with 2 test-code cases and 3 warnings.

### M3M4-03 | By H2
Ask: M3 confirms these.
- Language is `Finding.language`. Test-code flag is `Finding.in_test_code`.
- Insecure RNG and hard-coded key are findings with `hygiene_only` true and `hygiene_flags` containing `insecure_rng` or `hardcoded_key`.
- ECB is expressed as `mode = "ECB"` on the AES finding, not as a flag.
- SAFE decoys (AES-256-GCM, SHA-384, PBKDF2, HMAC-SHA256) produce SAFE assets, shown green.
Why: the page and the CBOM must use the same strings.
Preference: as stated.
Fallback: M3 names the values it uses. M4 adapts.

### M3M4-04 | By H6
Ask: M3 exposes `render_markdown_summary(result: ScanResult) -> str`. `write_markdown_summary(result, path)` writes that string. Output is sorted and deterministic.
Why: `/api/report.md` returns text.
Preference: as stated.
Fallback: M4 reads the file `write_markdown_summary` produces.

### M3M4-05 | By H6
Ask: M3 confirms how code findings enter the CBOM.
- Each occurrence is `evidence.occurrences[]` (file, line, snippet).
- When a key size came from a constant, the finding carries `extra["resolved_from_line"]`. M4 adds it to the evidence text.
- Test-code occurrences stay in the CBOM with property `quantumtrace:testCodeOnly = true`.
- Library findings become `library` components with a purl.
- Hygiene-only findings (insecure RNG, hard-coded key) are not CBOM components. They appear on the dashboard only.
Why: the CBOM is an inventory of cryptographic assets, and hygiene-only warnings are not primitives.
Preference: as stated.
Fallback: M4 includes hard-coded keys as `related-crypto-material` and omits `resolved_from_line`.

### M3M4-06 | By H6
Ask: for hard-coded key findings, M3 replaces the key literal in `snippet` with `<redacted>`. No key bytes in `extra`.
Why: key material must not reach the UI, the report or the CBOM.
Preference: as stated.
Fallback: M4 redacts string literals on lines flagged `hardcoded_key`.

### M3M4-07 | By H12
Ask: M3 confirms these. The scanner needs no external binaries. It honours `ScanOptions.exclude_dirs`. It yields findings in sorted path order.
Why: small Docker image, same output every run.
Preference: as stated.
Fallback: M3 names the binary. M4 adds it to Docker.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M3M4-01 | M3 | n/a | AGREED | Frontend split as stated. M3 touches only src/pages/CodeConfig.tsx and src/pages/code-config/. No npm dependency without telling M4. |
| M3M4-02 | M3 | n/a | CHANGED | M3 lists the needed content. Code assets: RSA-1024 signature in Python, Java and Go (each file also uses SHA-1), MD5, SHA-1 checksum, Ed25519, AES-128-ECB with hard-coded key, AES-256-GCM, SHA-384, HMAC-SHA256, PBKDF2. Hygiene-only: insecure RNG in Python, Java and Go, hard-coded AES key. One asset whose occurrences are all in a test path (in_test_code true). One library finding cryptography==46.0.5. Use file paths from sample-repos. |
| M3M4-03 | M3 | n/a | CHANGED | Language and in_test_code, the two hygiene flag strings (insecure_rng, hardcoded_key) and mode ECB as stated. Decoys: M3 emits findings for AES-256-GCM, SHA-384, HMAC-SHA256 and PBKDF2 and the engine assigns SAFE. SecureRandom, os.urandom and crypto/rand emit no finding, so no asset exists for them. |
| M3M4-04 | M3 | n/a | CHANGED | Signatures as stated: render_markdown_summary(result) -> str, write_markdown_summary(result, path), sorted and deterministic. Delivered after the rules and the sample-repos diff test (M3D-08), not by an hour. Until then /api/report.md needs a not generated yet response. |
| M3M4-05 | M3 | n/a | AGREED | M3 adds extra["resolved_from_line"] (int) when a size or transform came from a constant or parameter default (M3D-06). Library findings (manifests.py, P1) use kind_hint library with raw_name name==version. Hygiene-only findings stay off the CBOM as stated. |
| M3M4-06 | M3 | n/a | AGREED | The redaction ships with the hard-coded key rule, which is held until M1M3-02 is settled. No key bytes in extra. |
| M3M4-07 | M3 | n/a | CHANGED | No external binaries: as stated. The scanner takes one file per call, so exclude_dirs and path ordering are applied by M1's pipeline walk, not by M3. Within one file findings are sorted by line, rule id and raw name. |
| M3M4-02 | M4 | n/a | AGREED | Change accepted. The sample contains every listed case, with file paths from sample-repos. |
| M3M4-03 | M4 | n/a | AGREED | Change accepted. M4 expects no asset for SecureRandom, os.urandom or crypto/rand. |
| M3M4-04 | M4 | n/a | AGREED | Change accepted. No hour. /api/report.md returns a not generated yet response until M3D-08 exists. |
| M3M4-07 | M4 | n/a | AGREED | Change accepted. M4 expects exclusion and path order from the pipeline, not from the scanner. |
