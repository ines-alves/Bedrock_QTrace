---
name: qtrace-integration
description: Validate, commit, push, and integrate an authorized M1 QuantumTrace task into main using David Correia's configured Git profile and a verifiable contextual handoff. Use at M1 task integration boundaries.
---

# QuantumTrace task integration

The user authorized task branches and integration into existing `main`. Follow
repository protections and preserve other members' work; never force-push `main`.

1. Check branch, worktree, diff, owner boundaries, and acceptance results. Save
   the task handoff before committing and stage only this task's paths explicitly.
2. Confirm `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` identify
   `David Correia <davidfgcorreia@gmail.com>`. Check for environment overrides;
   do not change global settings. Use `area: imperative summary` commit messages
   and no Codex co-author trailers, including PR-generated squash/merge messages.
3. Fetch `origin/main`, reconcile new upstream work, rerun affected checks, and
   push the task branch. If commits are already published, prefer merging upstream
   into the task branch over rewriting published history.
4. Prefer a PR with the concrete behavior change and validation results. Save
   multiline CLI bodies to a temporary file and use `--body-file`. Merge a green
   M1-only task when allowed; do not bypass checks or protection rules.
   Where branch rules allow and PR checks pass, a local merge commit pushed to
   `main` preserves the user's author/committer identity. Verify the PR is then
   recognized as merged. Otherwise use the repository's permitted merge method
   and explicitly report any server-controlled committer identity.
5. If the GitHub API is unavailable but SSH Git works, inspect existing server-side
   PR/check references and retry the API once. If no PR/check/protection evidence
   is available, preserve the pushed branch and record the integration blocker;
   do not treat connectivity as permission to skip PR review or required checks.
6. Fetch again and verify the task commit (or its verified PR squash commit) is
   integrated into remote `main`. Save the PR URL and verified integration ancestor
   in the task file/status. Finalize checklists only after this verification.
7. A follow-up documentation commit may record observed integration evidence.
   Validate and integrate it through the same process; avoid a self-hash loop.
   Check the final commit externally and report it at the session boundary.

If authentication, permissions, protections, conflicts, or checks block integration,
leave the work on its task branch, mark the exact state in the handoff, and report
what remains. Sandbox escalations use the available approval mechanism; never
fabricate success or put tokens/credentials into documentation.
