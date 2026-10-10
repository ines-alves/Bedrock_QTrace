# M3M4 agreement

Between M3 (code scanner, markdown summary, Code & Config page) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

M4 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/DECISIONS.md` as correct. M4 does not ask for changes to it.

## Already decided by M1, adopted by M4 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `CryptoAsset` or `Finding`. Any change needs all four members. | DECISIONS 2026-10-10, initial contracts |
| Per-finding data | `Finding` already has `language` and `in_test_code`. The engine keeps every original `Finding`. M4 reads them through each asset's `finding_ids`. | `models.py`, `docs/PLAN.md` section 6 |
| Warnings | A warning that is not a cryptographic primitive uses `extra["hygiene_only"]` true and `extra["hygiene_flags"]` (list of strings). Hygiene-only warnings are excluded from the quantum score and readiness. | `docs/PLAN.md` section 6, DECISIONS scoring decision |
| Scanners supply facts | Scanners report what they see. The engine assigns tier and verdict. | `docs/PLAN.md` section 6 |
| Scan options | Default excluded directories: `.git`, `node_modules`, `venv`, `.venv`, `vendor`, `out`, `agents`. | `models.py` |
| Markdown owner | M3 owns `output/markdown.py` and `write_markdown_summary`. | `docs/PLAN.md` section 6 |

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
