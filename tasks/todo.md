## MCP server redesign (2026-09-18)

Plan: `.claude/plans/mcp-server-redesign-2026-09-18.md`
Tasks: `.claude/plans/mcp-redesign-tasks/` — 22 self-contained files.

- Entry point: `.claude/plans/mcp-redesign-tasks/START-HERE.md` (session protocol,
  commit convention, reset recovery)
- Progress: `.claude/plans/mcp-redesign-tasks/STATE.md`
- Index + dependency graph: that directory's `README.md`

Nothing started.

## Dependency refresh (2026-10-13)

Plan: `.claude/plans/dependency-refresh-2026-10-13.md`

- [x] Refresh the Python lockfile and runtime dependency minimums.
- [x] Prepare version 1.31.2 and its changelog.
- [x] Finish verification and create signed local commits.
- [ ] Push the branch and create the pull request.

Python 3.10 and 3.13: 2,889 passed, one skipped on each. Fix the existing MCP timeout
exception mismatch exposed on Python 3.10. Lint, formatting, lock consistency,
wheel/source builds and CLI version checks pass. User authorized committing all
remaining changes and opening the pull request.
