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
gh issue list --label type:bug,status:implementation-ready --state open \
  --search "no:assignee -label:status:blocked" --limit 50
```

`type:pipeline` tasks (changes to the factory itself) are picked up the same way. They're
usually docs (role/workflow `.md`), so TDD applies where there's testable behavior (add a
docs-consistency guard); a pure prose edit is verified by the existing docs tests + review.
A `type:bug` is fixed TDD-first: write a failing test that reproduces the defect, then fix it.

## Procedure

1. **Claim atomically** (self-assign AND mark in-progress in one step) so no one else grabs it:
   ```bash
   gh issue edit <TASK> --add-assignee @me --add-label status:in-progress --remove-label status:implementation-ready
   ```
2. Work in a **dedicated git worktree** on a new branch — never in the primary checkout or on
   `master` (agent runtimes with worktree tooling do this for you):
   ```bash
   git worktree add ../snf-task-<TASK> -b task/<TASK>-<slug>
   ```
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

If your change would **conflict with another open PR** (overlapping files, or a dependency
that's in review but not yet merged), open your PR **against that PR's branch** instead of
`master` — a "stacked" PR that shows only your diff and merges cleanly:

```bash
gh pr create --base <other-branch> --fill --title "<goal>" --body "Closes #<TASK> ..."
```

Once the base PR merges, GitHub retargets yours to `master` (when the base branch is deleted);
rebase if needed. Prefer this over hand-resolving conflicts or forcing the work to serialize.

## Guardrails

- **One task per PR**; one PR per branch. Never commit to `master`. Target `master` — unless the
  change would conflict with another open PR, in which case base it on that PR's branch (Outputs).
- Tests are required (TDD) — no implementation without a failing test first.
- Respect the Global Constraints in the plan/CLAUDE.md (Python ≥3.11, type hints, minimal deps).
- Follow the **code philosophy** ([CLAUDE.md](../../CLAUDE.md)): YAGNI (no speculative code),
  fail-fast with a clear error over defensive `if`s, and brief comments/PR summaries.
- If the task turns out to be wrong or blocked, stop and add `needs-human` with an explanation.

## Stop conditions

Stop when the PR is opened, or when there are no unassigned, ready, unblocked tasks.
