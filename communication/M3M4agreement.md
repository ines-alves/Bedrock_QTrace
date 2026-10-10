# M3M4 agreement

Between M3 (code scanner, markdown summary, Code & Config page) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

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
Why: M3 builds on the sample until H6 (M4 delivers the scaffold at H3, see `M4toAll.md`).
Preference: as stated.
Fallback: M4 includes 8 code assets across Python, Java, Go, with 2 test-code cases and 3 warnings.

### M3M4-03 | By H2
Ask: M3 confirms these.
- Language comes from the file extension (`.py`, `.java`, `.go`).
- Test-code flag comes from `Finding.in_test_code` via `finding_ids`.
- Non-quantum warnings are UNKNOWN-tier assets with flags `insecure_rng`, `hardcoded_key`, `ecb_mode`. They depend on `M1M4-01`.
- SAFE decoys (AES-256-GCM, SHA-384, PBKDF2, HMAC-SHA256) appear as SAFE assets, shown green.
Why: the page and the CBOM must use the same strings.
Preference: as stated.
Fallback: M3 names the fields the page needs. M4 asks M1.

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
- Hard-coded keys become `related-crypto-material`.
Why: the CBOM is an inventory and must not hide test code.
Preference: as stated.
Fallback: M4 omits `resolved_from_line`.

### M3M4-06 | By H6
Ask: for hard-coded key findings, M3 replaces the key literal in `snippet` with `<redacted>`. No key bytes in `extra`.
Why: key material must not reach the UI, the report or the CBOM.
Preference: as stated.
Fallback: M4 redacts string literals on lines flagged `hardcoded_key`.

### M3M4-07 | By H12
Ask: M3 confirms these. The scanner needs no external binaries. It ignores `.git`, `node_modules`, `venv`, `vendor`. It scans in sorted path order.
Why: small Docker image, same output every run.
Preference: as stated.
Fallback: M3 names the binary. M4 adds it to Docker.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
