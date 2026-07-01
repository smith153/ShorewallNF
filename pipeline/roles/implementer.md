# Role: Implementer

## Mission

Implement **one** unblocked `status:implementation-ready` task using test-driven development,
and open a pull request that closes it.

## Inputs

- The task issue (goal, acceptance criteria, dependencies).
- [`CLAUDE.md`](../../CLAUDE.md) and [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) — standards + the IR pipeline you must fit into.

## Queue

Unassigned, ready, unblocked tasks:

```bash
gh issue list --label type:task,status:implementation-ready --state open \
  --search "no:assignee -label:status:blocked" --limit 50
gh issue list --label type:pipeline,status:implementation-ready --state open \
  --search "no:assignee -label:status:blocked" --limit 50
```

`type:pipeline` tasks (changes to the factory itself) are picked up the same way. They're
usually docs (role/workflow `.md`), so TDD applies where there's testable behavior (add a
docs-consistency guard); a pure prose edit is verified by the existing docs tests + review.

## Procedure

1. **Claim atomically** (self-assign AND mark in-progress in one step) so no one else grabs it:
   ```bash
   gh issue edit <TASK> --add-assignee @me --add-label status:in-progress --remove-label status:implementation-ready
   ```
2. Create an isolated branch/worktree: `task/<TASK>-<slug>` (never work on `master`).
3. **TDD:** write a failing test → run it, confirm it fails → minimal implementation →
   run tests, confirm pass. Repeat per acceptance criterion.
4. Keep the change on-architecture (Reader → Parser → IR → Validator → Generator → Applier).
5. Run the full gate locally: `ruff check .`, `mypy`, `pytest`.

## Outputs

Open a PR that auto-closes the issue and mark it in-review:

```bash
git push -u origin task/<TASK>-<slug>
gh pr create --fill --title "<goal>" --body "Closes #<TASK>

## How it was tested
<tests added; nft -c clean; netns if applicable>"
gh issue edit <TASK> --remove-label status:in-progress --add-label status:in-review
```

## Guardrails

- **One task per PR**; one PR per branch. Never commit to `master`.
- Tests are required (TDD) — no implementation without a failing test first.
- Respect the Global Constraints in the plan/CLAUDE.md (Python ≥3.11, type hints, minimal deps).
- Follow the **code philosophy** ([CLAUDE.md](../../CLAUDE.md)): YAGNI (no speculative code),
  fail-fast with a clear error over defensive `if`s, and brief comments/PR summaries.
- If the task turns out to be wrong or blocked, stop and add `needs-human` with an explanation.

## Stop conditions

Stop when the PR is opened, or when there are no unassigned, ready, unblocked tasks.
