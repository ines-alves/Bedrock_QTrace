# Task record template

Copy this structure when adding a task; existing M1 plans already use the same lifecycle.

## Plan before implementation

Record task ID, owner, priority, goal, branch, base commit, relevant specification
sections, dependency commits/interfaces, owned files, implementation steps, public
contract effects, error behavior, and the acceptance checks needed for this change.
Refresh the plan against current repo facts before coding.

## Completion checklist

- [ ] Plan refreshed before implementation; dependencies checked.
- [ ] Task branch created from current `origin/main`.
- [ ] Planned behavior implemented within ownership boundaries.
- [ ] Meaningful acceptance checks passed; exact commands/results saved.
- [ ] Starter inputs unchanged; contract changes agreed if already frozen.
- [ ] Handoff and status updated before commit.
- [ ] Correct author/committer; no Codex co-author trailer.
- [ ] Task branch pushed; integration checks passed.
- [ ] Remote `main` integration verified; checklist/status finalized.

## Results and contextual handoff

Record changed behavior/interfaces; validation commands, results, and limitations;
deferred work and exact blockers; branch, commit, PR, and remote integration evidence;
and which files the next session should read. Never store credentials or private keys.

For the final documentation commit, identify it by its title/PR and a verified
ancestor rather than trying to embed its own hash inside itself. Confirm the final
hash externally in the final response or next session's status refresh.

## Next-session prompt

Provide a directly usable prompt naming the member, next task, plan/handoff files,
required skills, branch workflow, acceptance checks, and the session boundary.
