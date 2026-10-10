# M1 to all

Status: OPEN

From M1. Rules: README.md. Replies dated 2026-10-10; kickoff H0 has not been
provided, so Hour is recorded as unknown rather than inventing elapsed time.
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
| M1D-02 | All | Verified KB/loader on the tested 1.3 branch, integrated at the 1.8 core milestone | H4 |
| M1D-03 | All | Engine preserves raw findings/metadata, classifies and scores once, stable IDs | H6 |
| M1D-04 | All | Pipeline, native JSON/roadmap, CLI; tasks 1.9/1.11/1.10 milestone | H6 |
| M1D-05 | All | Golden contribution schema available in docs/GOLDEN.md and docs/golden.schema.json; evaluator is task 1.12 | H2 |
| M1D-06 | All | Honest golden metrics and full starter acceptance, task 1.12/integration milestone | H12 |

## 3. Needs

| ID | From | What | By |
|---|---|---|---|
| M1N-01 | M2 | Registered adapters, verified TLS/SSH registry aliases/codepoints, session evidence, parser count confirmation | H4 |
| M1N-02 | M3 | Registered code/config adapters, SAFE-decoy tests, redacted evidence, Markdown writer | H6 |
| M1N-03 | M4 | Registered cloud adapters and verified registry, strict CBOM writer/validator, shared-model API/UI consumption | H6 |
| M1N-04 | M2, M3, M4 | Owner-confirmed golden rows in documented format and tested branch commit references | H12 |
| M1N-05 | M4 | Confirm changed M1M4 responses, especially raw-to-derived warning presentation and per-key CBOM material construction | H4 |

## 4. Promises

- Scanners detect; engine classifies and scores. Findings and arbitrary JSON extra evidence are retained.
- Engine-derived hygiene advice is in asset rationale/recommendations; raw Finding.extra stays unchanged.
- Link cloud policy evidence by listener resource_id and certificates by certificate_arns, not assumed equal ARNs.
- One scored algorithm representation per scoring group; M4 can build key material CBOM entries from retained raw key evidence.
- Unknown authentication prevents an otherwise SAFE hybrid session being reported SAFE.
- Task branches are tested and pushed; main advances at significant milestones with cumulative checks and protections.
- No private key material, fabricated standards status, or claimed implementation before validation.
- docs/DECISIONS.md is local-only by user request. Shared conclusions live in communication replies and docs/PLAN.md.
- H milestones above are planning targets, not measured elapsed-time or completion claims.

## 5. Confirmation checklist

| ID | Statement | Reply from |
|---|---|---|
| M1C-01 | M1 session evidence and registry needs/deliverables are correct | M2 |
| M1C-02 | M1 code evidence and Markdown needs/deliverables are correct | M3 |
| M1C-03 | M1M4 replies and cloud/CBOM/API needs/deliverables are correct | M4 |
| M1C-04 | Section 4 and milestone branch process are acceptable | M2, M3, M4 |

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
