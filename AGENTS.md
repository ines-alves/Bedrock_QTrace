# QuantumTrace repository instructions

Read `docs/PLAN.md` for the product specification and ownership map. For M1 work,
also read `agents/IMPLEMENTATION.md`, `agents/STATUS.md`, and the active task file
under `agents/tasks/`. Approved updates are recorded in `docs/DECISIONS.md`.

## Ownership and contracts

- The current member is **M1**, owner of packaging, Makefile, shared models,
  scanner base, algorithm/scoring KB and loader, engine, pipeline, CLI, native
  report/roadmap, evaluation, and repository workflow documentation.
- M2 owns network scanners and TLS/SSH registries; M3 owns code/config scanners
  and Markdown/SARIF; M4 owns cloud scanners/registry, CBOM, API/UI, and packaging
  for deployment. See section 5 for exact boundaries. Record cross-owner requests
  in `docs/DECISIONS.md` and the handoff; do not silently implement them.
- Establish the initial section 6 contracts in task 1.2, including the approved
  `ScanOptions` and optional typed roadmap additions. After that task, freeze
  contracts; further changes require team agreement. Never redefine shared models.
- Scanners detect and yield `Finding | ScanError`. Only the engine and KB assign
  tiers, recommendations, or scores.
- `sample-repos/`, `cloud-posture/`, and `network-capture/` are read-only inputs.
  Do not modify them, expose private keys, or commit generated reports or secrets.

## Applicable local skills

Read skills explicitly; automatic discovery of this writable `agents/` directory
is not assumed. Do not write to protected `.agents/` or `.codex/` directories.

- Every M1 task: `agents/skills/qtrace-task-cycle/SKILL.md`.
- Contracts, KB, engine, pipeline, CLI, reporting, evaluation:
  `agents/skills/qtrace-core-engine/SKILL.md`.
- Committing, pushing, merging, or validating integration:
  `agents/skills/qtrace-integration/SKILL.md`.

## Implementation invariants

- Python 3.12, type hints, Pydantic v2, Ruff with import sorting and line length 110.
- Preserve deterministic IDs and ordering; timestamps do not participate in IDs.
- Never invent standards status, OIDs, codepoints, or AWS policy mappings. Verify
  primary sources during the owning task and keep uncertainty explicit.
- A SAFE hybrid KEX with unobservable authentication has an UNKNOWN overall verdict
  unless an observed component is CRITICAL or MEDIUM. Do not guess certificate keys.
- Preserve offered/negotiated and per-source evidence through aggregation.
- Exclude plaintext/hygiene-only warnings and derived protocol containers from
  quantum scoring; containers summarize their scored components.
- Tests use local fixtures and no network. Test meaningful behavior, run the checks
  available at the current stage, and record unavailable checks honestly.

## Task and Git lifecycle

- Plan each task in its task file before implementation. The accepted roadmap
  authorizes routine implementation choices; do not add a recurring approval gate.
- Use a short-lived `m1/<task-id>-<topic>` branch from current `origin/main`.
  `main` is the integration branch; there is no request to create `master`.
- Use the existing Git profile: **David Correia <davidfgcorreia@gmail.com>** for
  both author and committer. Do not add Codex co-author trailers. Inspect identity
  before committing rather than changing global Git settings.
- The user authorized pushing tested M1 task branches and integrating them into
  `main`. Prefer a PR; self-merge green changes within M1 scope when allowed.
  Do not force-push `main` or bypass repository protections.
- Save contextual handoffs before committing. Mark a task complete only after
  verifying integration into remote `main`. A local commit alone is not completion.
- The user chose **one fresh session per task**. At the task boundary, save results,
  blockers, and an exact restart prompt, then end the session. The user opens the
  new session. Do not claim to clear context or launch concurrent agents.
- If Git/network/permissions block integration, finish all available work, record
  the exact blocker, and report it. Never fabricate a push, merge, or test result.
