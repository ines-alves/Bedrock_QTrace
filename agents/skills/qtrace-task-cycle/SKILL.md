---
name: qtrace-task-cycle
description: Plan and hand off an M1 QuantumTrace repository task with durable checklists and a fresh session at each task boundary. Use for tasks listed in agents/STATUS.md.
---

# QuantumTrace task cycle

Read root `AGENTS.md`, `agents/STATUS.md`, `agents/IMPLEMENTATION.md`, the previous
handoff, and the active task plan. Resolve repository facts before updating the plan.

1. Check Git state and fetch `origin/main`. Preserve unrelated changes. Save the
   task's concrete plan before implementing it; record its base and dependencies.
2. Use a task branch named in the plan. Implement only the current M1 task. Skills
   and task files support the user-approved roadmap; no recurring permission step
   is required for routine authorized work.
3. Run the task's acceptance checks and applicable repository checks. Record exact
   results, including unavailable tooling or missing owner implementations. Mark
   blocked dependency gates separately from locally passed behavior tests.
4. Save results, interfaces changed, known issues, Git integration references, and
   the exact next-session prompt in the task record. Update `agents/STATUS.md`.
5. Use `agents/skills/qtrace-integration/SKILL.md` for committing and merging. A
   task is complete only after remote integration is verified; finalize its
   checklist and the implementation checklist together.
6. End this session after the task handoff. The user opens the next fresh session;
   do not claim to clear context or start the next implementation in this session.

Task structure: `agents/tasks/TEMPLATE.md`. Current task plans: `agents/tasks/`.
If integration is blocked, finish unaffected authorized work and record the exact
condition and restart instructions. Preserve the same task as active until resolved.
