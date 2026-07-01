# Contributing to ShorewallNF

Both humans and AI agents are welcome. ShorewallNF is built by a pipeline of AI agents
coordinated through GitHub, but ordinary human contributions (issues, PRs, reviews) work
exactly as you'd expect.

## How the work is organized

Work flows through two phases (full detail in [`../pipeline/workflow.md`](../pipeline/workflow.md)):

1. **Refinement** — an **Epic Author** proposes epics; a human approves them; an **Epic
   Decomposer** breaks each into tasks; a **Task Groomer** validates tasks to
   `implementation-ready`.
2. **Delivery** — an **Implementer** picks up a ready task, an open PR gets a **Code Review**,
   a **Fixer** addresses feedback, and **Merge-readiness** flags green + approved PRs for a
   human to merge.

Labels track type/status/area — see [`../pipeline/labels.md`](../pipeline/labels.md).

## Volunteer an AI agent for a session

This is the primary contribution model. Point your own AI agent at the repo and have it play
one role for a session:

1. `gh auth login` (the roles drive GitHub through the `gh` CLI).
2. Pick a role from [`../pipeline/README.md`](../pipeline/README.md).
3. Run it: in Claude Code, `/‹role›` (e.g. `/implementer`); in any other runtime, follow
   `pipeline/roles/‹role›.md` directly.

## Contributing by hand

- **Dev setup:**
  ```bash
  python -m pip install -e ".[dev]"
  python -m ruff check . && python -m mypy && python -m pytest -v
  ```
- **Standards:** Python ≥ 3.11, full type hints, `mypy --strict`, `ruff`, TDD. Minimal runtime
  deps (an ADR is required to add one). See [`../CLAUDE.md`](../CLAUDE.md).
- **Workflow:** branch → PR; **never commit to `master`**. Use a git worktree for isolation.
  One task per PR, referenced with `Closes #NN`. Conventional Commit messages.

## Human gates

Two steps always require a human, by design:

1. **Approving epics** — a maintainer moves an epic to `status:implementation-ready` before it
   is decomposed.
2. **Merging to `master`** — branch protection requires green CI **and** a human approving
   review (via [`../.github/CODEOWNERS`](../.github/CODEOWNERS)). An AI review never satisfies
   this on its own.
