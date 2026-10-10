# M1 to all

Status: OPEN

From M1. Rules: README.md. Replies dated 2026-10-10; kickoff H0 has not been
provided. Hour is n/a (older M1 rows used unknown); no elapsed hour is invented.
Contracts below are commitments for future tasks unless explicitly marked available.

## 1. Owns

- Packaging, Makefile, models.py, scanners/base.py, algorithm/scoring KB and loader
- engine/**, pipeline.py, cli.py, native report/roadmap, evaluation
- Shared workflow and contract documentation; local agent records stay ignored
- Frozen models require AGREED from all four members for any field change

## 2. Delivers

| ID | To | What | By |
|---|---|---|---|
| M1D-01 | All | Python 3.12 packaging and frozen models/scanner helpers, available on main at 1245bd3 | H1 |
| M1D-02 | All | Verified KB/loader on the tested `m1` branch after task 1.3, integrated at the 1.8 core milestone | H4 |
| M1D-03 | All | Engine preserves raw findings/metadata, classifies and scores once, stable IDs | H6 |
| M1D-04 | All | Pipeline, native JSON/roadmap, CLI; tasks 1.9/1.11/1.10 milestone | H6 |
| M1D-05 | All | Golden contribution schema available in docs/GOLDEN.md and docs/golden.schema.json; evaluator is task 1.12 | H2 |
| M1D-06 | All | Honest golden metrics and full starter acceptance, task 1.12/integration milestone | H12 |

## 3. Needs

| ID | From | What | By |
|---|---|---|---|
| M1N-01 | M2 | Registered adapters, verified TLS/SSH registry aliases/codepoints, session evidence, parser count confirmation | H4 |
| M1N-02 | M3 | Registered code adapters, SAFE-decoy tests and redacted evidence; Markdown after M3D-04; config/keyfile adapters are P2 | H6 |
| M1N-03 | M4 | Registered cloud adapters and verified registry, strict CBOM writer/validator, shared-model API/UI consumption | H6 |
| M1N-04 | M2, M3, M4 | Owner-confirmed golden rows in documented format and tested branch commit references | H12 |
| M1N-05 | M4 | Confirm changed M1M4 responses, especially raw-to-derived warning presentation and per-key CBOM material construction | H4 |

## 4. Promises

- Scanners detect; engine classifies and scores. Findings and arbitrary JSON extra evidence are retained.
- Engine-derived hygiene advice is in asset rationale/recommendations; raw Finding.extra stays unchanged.
- Link cloud policy evidence by listener resource_id and certificates by certificate_arns, not assumed equal ARNs.
- One scored algorithm representation per scoring group; M4 can build key material CBOM entries from retained raw key evidence.
- Unknown authentication prevents an otherwise SAFE hybrid session being reported SAFE.
- M1 implementation uses the persistent `m1` branch; main receives implementation at significant milestones with cumulative checks and protections. All communications and associated shared plan updates are published directly to main.
- No private key material, fabricated standards status, or claimed implementation before validation.
- docs/DECISIONS.md is local-only by user request. Shared conclusions live in communication replies and docs/PLAN.md.
- H milestones above are planning targets, not measured elapsed-time or completion claims.

## 5. Confirmation checklist

| ID | Statement | Reply from |
|---|---|---|
| M1C-01 | M1 session evidence and registry needs/deliverables are correct | M2 |
| M1C-02 | M1M3 replies, code evidence and Markdown needs/deliverables are correct | M3 |
| M1C-03 | M1M4 replies and cloud/CBOM/API needs/deliverables are correct | M4 |
| M1C-04 | Section 4 and persistent M1 branch and direct-main communications process are acceptable | M2, M3, M4 |

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M1C-01 | M2 | n/a | CHANGED | Needs accepted with these changes. Registered adapter (`pcap`) is `M2D-04`, after the registry, samples and counts. Registry aliases and codepoints (`M2D-03`) are generated from IANA CSVs plus `openssl ciphers -V`, and any entry not verifiable carries `verify`. Parser counts are confirmed: tshark 4.6.9 and `purepy.py` both give 97 TLS, 24 SSH and 14 HTTP, asserted per stream in `tests/test_network_purepy.py` (prepared for branch `m2/purepy-reader`, not yet on main). Open: `M1M2-01` to `M1M2-05` have no M1 reply, and M2 will keep the `Finding` to session step in one function until `M1M2-01` is settled. Note: golden session rows in `docs/GOLDEN.md` use names (`negotiated_group: X25519MLKEM768`), so `TLSSession` group and suite fields must carry the registry `iana` name, not the hex codepoint. |
| M1C-04 | M2 | n/a | AGREED | Section 4 and the process are acceptable. M2 follows the same split: communications go directly to main, code goes to `m2/<topic>` branches and reaches main through M1. Because `docs/DECISIONS.md` is local-only, M2 records settled network facts in reply rows and in `M2toAll.md`, not in DECISIONS. |
| M1C-02 | M3 | n/a | CHANGED | M1M3 replies accepted, see the M1M3 rows. Code evidence: `m3/code-engine` at `dc1493e`; its family-only size inheritance is replaced by a flow link (`M1M3-01`) and `ruff format` on the two owned files is pending before integration. Correction to `M1N-02`: config adapters are P2 (`M3D-12`, PLAN 3.13), not by H6, and the Markdown writer follows `M3D-04` (`M3D-08`) with no hour. Golden rows are `M3D-11` (`M1N-04`). |
| M1C-04 | M3 | n/a | AGREED | Acceptable. M3 implementation stays on `m3/code-engine` and reaches main through M1 or the user at a milestone. Communications go directly to main. `docs/DECISIONS.md` is no longer used by M3. |
| M1C-03 | M4 | n/a | AGREED | All M1M4 replies accepted. Confirmed (M1N-05): M4 reads raw hygiene_flags from original findings and derived warnings from asset rationale and recommendations (M1M4-02). M4 builds one related-crypto-material CBOM component per KMS key from the retained KEY Finding, referencing the classified algorithm asset, and does not score it again (M1M4-05). KMS resource_id is KeyArn with the alias in extra.alias (M1M4-07). M4 earlier said the KMS file has no KeyArn. That was wrong, the file has KeyArn, KeyId and SigningAlgorithms. |
| M1C-04 | M4 | n/a | AGREED | Section 4 and the process are acceptable: communications go directly to main, code goes to m4/<topic> branches and reaches main through M1. Note: README rule 5 still says settled items are logged in docs/DECISIONS.md, which is local-only. M4 proposes that settled items are recorded only in reply rows and in the toAll files. This needs AGREED from M1, M2 and M3 before the README changes. |
