# M4 to all

Status: OPEN

From M4. Rules: `README.md`. This file is also the template for `M1toAll.md`, `M2toAll.md`, `M3toAll.md`: same four sections, same checklist format.

## 1. Owns

- `scanners/cloud/**`, `kb/cloud_registry.yaml`
- `output/cyclonedx.py`
- `api/**`
- `frontend/**` (except `src/pages/CodeConfig.tsx` and `src/pages/code-config/`, owned by M3)
- `Dockerfile`, `.dockerignore`, root `README.md`, `scripts/demo.sh`
- `tests/fixtures/cloud/`, `tests/fixtures/scan_result_sample.json`, `tests/test_cloud_*`, `tests/test_output_*`, `tests/test_api_*`
- Cloud section of `tests/golden/expected.yaml`
- Pitch deck and backup recording

## 2. Delivers

| ID | To | What | By |
|---|---|---|---|
| M4D-01 | All | `scan_result_sample.json`, a valid `ScanResult` with about 30 assets, 5 TLS sessions, 2 SSH sessions | H1.5 |
| M4D-02 | All | Dashboard running on the sample (`npm run dev`, `/api/result`) | H3 |
| M4D-03 | M3 | Scaffold, generated TS types, `useScanResult()`, `TierBadge`, sortable table, empty Code & Config route | H3 |
| M4D-04 | M1 | KMS, load balancer and ACM adapters matching `docs/PLAN.md` Appendix D.5 | H6 |
| M4D-05 | M1 | `build_cbom` and `validate_cbom`, strict-validated for CycloneDX 1.6 | H6 |
| M4D-06 | All | `/api/scan`, `/api/cbom`, `/api/report.md`, `/api/validate` | H6 |
| M4D-07 | All | Network, Cloud, CBOM, Roadmap pages on real data | H18 |
| M4D-08 | All | Dockerfile and README that run on a clean machine | H18 |
| M4D-09 | All | `scripts/demo.sh`, deck, backup recording | H22 |

## 3. Needs

| ID | From | What | By |
|---|---|---|---|
| M4N-01 | M1 | Items `M1M4-01` to `M1M4-07` settled (extra keys, hygiene derivation, listener link, aliases, KMS finding, plaintext, routing) | H4 |
| M4N-02 | M1 | Valid enums and `asset_id` (`M1M4-08`), `scoring.yaml` (`M1M4-09`), roadmap phases (`M1M4-10`), CLI and API handshake (`M1M4-11`) | H6 |
| M4N-03 | M1 | Golden file schema (`M1M4-13`) and branch process (`M1M4-14`) | H2 |
| M4N-04 | M2 | Real session samples and value lists (`M2M4-01`, `M2M4-02`) | H2 |
| M4N-05 | M2 | Registry access (`M2M4-04`) | H4 |
| M4N-06 | M2 | Fixture pcaps (`M2M4-06`) | H12 |
| M4N-07 | M3 | Sample needs and flag names (`M3M4-02`, `M3M4-03`) | H2 |
| M4N-08 | M3 | `render_markdown_summary` (`M3M4-04`), redaction (`M3M4-06`) | H6 |

## 4. Promises

- M4 reads only `ScanResult`, `Finding` and `TLSSession`. M4 does not parse pcaps, code or other raw sources owned by others.
- Cloud adapters report facts. Only the engine assigns tier, threat and score.
- M4 uses only the helpers in `scanners/base.py`.
- M4 emits `source_timestamp` from the dump's `GeneratedAt` and never computes expiry. The engine does.
- M4 accepts the frozen contract in `models.py` and `docs/DECISIONS.md`. M4 does not request model changes.
- M4 pushes only to `m4/<topic>` branches.
- The UI shows `pq_status` and `verdict_tier` as separate columns.
- M4 never prints or stores key material.
- All M4 output is sorted and uses hash-based ids.
- M4 reports a task done only after its tests and lint pass.
- M4 announces any change to a shared component before making it.
- Anything unverified (validator extras, image tag, AWS policy tables, `SYMMETRIC_DEFAULT`) is marked verify and checked against the primary source.

## 5. Confirmation checklist

Reply with a row in the table below, using the checklist ID.

| ID | Statement | Reply from |
|---|---|---|
| M4C-01 | Section 2 rows to M1 and Section 3 rows from M1 are correct | M1 |
| M4C-02 | Section 2 rows to All and Section 3 rows from M2 are correct | M2 |
| M4C-03 | Section 2 rows to M3 and Section 3 rows from M3 are correct | M3 |
| M4C-04 | Section 4 is acceptable | M1, M2, M3 |

When all rows have AGREED or CHANGED from every named member, M4 sets `Status: ALIGNED` at the top.

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M4C-01 | M1 | unknown | CHANGED | M1 dependencies/deliverables accepted subject to M1M4 replies, docs/GOLDEN.md, and milestone integration; H times are targets, not claims of implemented code. |
| M4C-04 | M1 | unknown | AGREED | Section 4 accepted. Preserve raw facts and source_timestamp; keep verdict and pq_status distinct, no keys, frozen models, verified mappings, deterministic output and tested member branches. |
