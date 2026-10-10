# M1 implementation plan

Approved 2026-10-10. Product specification: [PLAN.md](../docs/PLAN.md).
Live execution state: [STATUS.md](STATUS.md).

## Goal and boundaries

Deliver M1's core, risk engine, CLI, native report, and accuracy evaluation for
QuantumTrace. Support M2–M4 through stable contracts and integration; their scanner,
CBOM, API/UI, and deployment implementations remain under their ownership.

The initial repository contains the specification and starter datasets, with no
application implementation. Target Python 3.12 despite current system Python 3.14.
Provision a project environment in task 1.1. Keep sample inputs unchanged.

## Ordered implementation checklist

Each task file contains its implementation plan, acceptance checklist, and handoff.
Unchecked means not verified as integrated; consult the status tracker for progress.

| Integrated | Task | Deliverable | Plan |
|---|---|---|---|
| [ ] | M1-00 | Repository instructions, skills, task plans, workflow | [M1-00](tasks/M1-00.md) |
| [ ] | 1.1 | Project foundation and Python 3.12 environment | [1.1](tasks/1.1.md) |
| [ ] | 1.2 | Shared contracts and scanner base; initial freeze | [1.2](tasks/1.2.md) |
| [ ] | 1.3 | Algorithm/scoring KB and validated loader | [1.3](tasks/1.3.md) |
| [ ] | 1.4 | Normalization and parameter extraction | [1.4](tasks/1.4.md) |
| [ ] | 1.5 | Composite decomposition | [1.5](tasks/1.5.md) |
| [ ] | 1.6 | Central classification and recommendations | [1.6](tasks/1.6.md) |
| [ ] | 1.7 | Deterministic evidence aggregation | [1.7](tasks/1.7.md) |
| [ ] | 1.8 | Scoring and risk summaries | [1.8](tasks/1.8.md) |
| [ ] | 1.9 | Router, orchestration, and session views | [1.9](tasks/1.9.md) |
| [ ] | 1.11 | Native JSON report and typed roadmap | [1.11](tasks/1.11.md) |
| [ ] | 1.10 | CLI and output integration | [1.10](tasks/1.10.md) |
| [ ] | 1.12 | Golden accuracy evaluation | [1.12](tasks/1.12.md) |
| [ ] | integration | Full starter-kit acceptance checkpoint | [integration](tasks/integration.md) |
| [ ] | 1.13 | Optional JSON stdout and CI threshold exits | [1.13](tasks/1.13.md) |

Implement 1.11 before 1.10 so the CLI can use the native writer. P0/P1 and the
integration checkpoint precede optional 1.13. The H6 end-to-end gate requires real
M2–M4 adapters; fake-scanner tests verify M1 plumbing but do not satisfy that gate.

## Contract decisions for task 1.2

- Preserve section 6 models, Scanner methods, `analyze()`, and `run()` as public
  integration boundaries. Include SSH, ACM, and plaintext enum additions.
- Define `ScanOptions` with default directory exclusions (`.git`, `node_modules`,
  `venv`, `.venv`, `vendor`, `out`, `agents`) and an optional scanner-name selection.
  Use a validated Pydantic model; reject unknown selected scanner names explicitly.
- Use `probes=None` rather than a mutable list default in `run()`. Probe support
  remains dependent on M2's optional adapter; never silently ignore requested probes.
- Define `RoadmapItem` with phase (0–3), action, asset IDs, and occurrence count.
  Add optional `ScanResult.roadmap`, omitted from JSON when absent. This avoids an
  untyped report-only payload outside the shared contract.
- Establish documented `Finding.extra` conventions: scanner origin/state/public
  exposure, hygiene flags, source timestamp, and session observability data. Preserve
  these through internal engine records instead of discarding them during dedupe.
- Initial contracts freeze at the end of 1.2. Later additions require team agreement.

## Core behavior

- Decompose before normalization. Canonical identity includes parameters, asset
  type, and usage; stable IDs do not depend on traversal order or timestamps.
- Aggregate unique evidence while retaining per-finding confidence, source, and
  offered/negotiated status. Use maximum applicable exposure and maximum confidence
  among relevant findings per scoring group; source summaries use only that source's
  findings. Occurrence factor counts unique evidence, not duplicate detector emissions.
- Use section 7.5 weights, occurrence cap, broken multiplier, and negotiated HNDL
  floor. Exclude derived protocol containers and plaintext/hygiene-only/library
  records from score/readiness denominators; unknown crypto remains scoreable.
- Composite verdict precedence: CRITICAL, MEDIUM, UNKNOWN, SAFE. A hybrid with
  unobservable authentication is UNKNOWN overall; known RSA/ECDSA authentication
  makes it CRITICAL. Its SAFE KEX keeps its own classification and HNDL status.
- Session IDs and component links remain stable. Atomic hybrid KEX classification
  must not be overridden by the vulnerable classical half of its combiner.
- Timestamp metadata may vary; classified content, IDs, scores, and roadmap order
  must remain deterministic for the same findings and reference time.
- Use source dump time for expiry when available, otherwise scan start time. Never
  silently use the current date inside deterministic engine operations.
- Scanner failures become `ScanError`; preserve usable results and expose incomplete
  coverage. Missing optional writers or requested adapters produce explicit errors.
- Fact verification happens during the owning task against primary sources. Record
  verified versions/dates; unknown inputs remain UNKNOWN rather than guessed.

## Validation and integration

Task acceptance checks grow with the project: workflow validation in M1-00;
installation/import/lint/tests in 1.1; behavior tests afterward; evaluation once
1.12 exists. Do not claim `make check` passed before it is implemented and applicable.

Final M1 acceptance requires ≥95% precision and recall on owner-confirmed starter
golden data, correct SAFE decoys and TLS/SSH/cloud counts, valid native JSON and M4
CBOM, compatible M4 consumption, and a full starter scan under 60 seconds.

Use per-task branches, your Git identity, green checks, PR integration, and remote
verification as described in [the integration skill](skills/qtrace-integration/SKILL.md).
Save handoffs and end each task session. New sessions read files rather than relying
on previous conversation context.
