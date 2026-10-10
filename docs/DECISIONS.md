# QuantumTrace decisions

The user-approved M1 implementation plan refines `docs/PLAN.md`. Preserve team
ownership and record further changes here with date, member, and affected behavior.

| Date | Member | Decision |
|---|---|---|
| 2026-10-10 | M1 / user | Keep coding-agent guidance in the shared plan and optional local root instructions; remove the redundant root guidance file and its scaffolding requirement from all plans. |
| 2026-10-10 | M1 / user | Keep root `AGENTS.md` and the entire `agents/` directory local-only and Git-ignored. Remove them from current Git tracking while preserving local files; do not rewrite history. Shared docs must not require these files in teammates' checkouts. |
| 2026-10-10 | M1 / user | Use existing `main`, not a new `master`, as integration branch. Use per-task `m1/<task-id>-<topic>` branches and verified green integration. |
| 2026-10-10 | M1 / user | Use configured David Correia author/committer identity; add no Codex co-author trailers. |
| 2026-10-10 | M1 / user | Save a task plan before implementation, checklist and handoff at task end, and start the next task in a fresh user-opened session. |
| 2026-10-10 | M1 / user | Put workflow/skills in writable `agents/`; root `AGENTS.md` explicitly routes to them because `.agents/` is protected. |
| 2026-10-10 | M1 / user | SAFE hybrid KEX with unobservable authentication has UNKNOWN overall verdict unless an observed component is CRITICAL or MEDIUM. Correct the conflicting golden CRITICAL assumption. |
| 2026-10-10 | M1 / approved plan | Establish `ScanOptions`, `probes=None`, and an optional typed `ScanResult.roadmap` in initial task 1.2 contracts; freeze after 1.2. Native reports remain valid ScanResult documents. |
| 2026-10-10 | M1 / approved plan | Exclude derived protocol containers, plaintext/hygiene-only warnings, and libraries from quantum score/readiness denominators; unknown crypto remains scoreable. Preserve per-finding scoring metadata. |
| 2026-10-10 | M1 / implementation default | Aggregate confidence as the maximum among relevant findings and exposure as the maximum applicable exposure. Per-source summaries restrict evidence first; count unique occurrences. |
| 2026-10-10 | M1 / approved plan | Use dump timestamp for expiry when present, otherwise scan start time. Verify factual mappings/status in owning tasks; leave uncertainty explicit. |
| 2026-10-10 | M1 / approved plan | Implement native writer 1.11 before CLI 1.10; optional 1.13 follows green P0/P1 and the real-adapter integration checkpoint. |
| 2026-10-10 | M1 / user | Continue task 1.2 in the current session at the user's explicit request; keep task planning and integration lifecycle, and save the next task handoff at completion. |
| 2026-10-10 | M1 / initial contracts | Establish and freeze section 6 models and scanner helpers in task 1.2, including ScanOptions.exclude_dirs/scanner_names and RoadmapItem.phase/action/asset_ids/occurrence_count. Unknown scanner selections raise ValueError after adapters load; registry and selection sort by name. Finding.extra evidence conventions are documented in section 6 for M2–M4 consumption. Further contract changes, including optional additions, require team agreement. |
| 2026-10-10 | M1 / implementation default | Raise the Pydantic minimum to 2.12 for public Field(exclude_if=...) support; omit absent roadmap while preserving other nullable evidence and typed serialization schemas. Locked Pydantic remains 2.14.0. |
