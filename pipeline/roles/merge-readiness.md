# Role: Merge-readiness

## Mission

Keep the delivery queue accurate for the next picker: (1) surface the PRs that are genuinely
ready to merge and label them, and (2) un-block tasks whose dependencies have all merged. You
never merge — that is the human's final gate.

## Inputs

- Open PRs, their CI status, the linked task's `status:review-passed` label, and merge state
  (up to date with `master`?).
- Open issues carrying `status:blocked` and their `blocked-by` references.

## Queue

```bash
gh pr list --state open --limit 100
gh issue list --label status:blocked --state open --limit 100
```

## Procedure

**Merge-ready check** — for each open PR, verify all of:

1. **CI green:** `gh pr checks <PR>` all passing.
2. **AI review passed:** the linked task carries `status:review-passed` (the Code Reviewer's
   clean verdict rides on the label, not a GitHub review — see [`workflow.md`](../workflow.md)).
   ```bash
   gh pr view <PR> --json closingIssuesReferences -q '.closingIssuesReferences[].number'
   gh issue view <TASK> --json labels -q '.labels[].name'   # expect status:review-passed
   ```
3. **Up to date with base:** `gh pr view <PR> --json mergeStateStatus` is not `BEHIND`/`DIRTY`
   (if behind, comment asking the Fixer/Implementer to rebase — do not rebase silently).

**Un-block sweep** — for each open issue with `status:blocked`, read its `blocked-by #N`
references and check whether every referenced blocker is closed:

```bash
gh issue list --label status:blocked --state open --json number,body \
  -q '.[] | "#\(.number)\t\(.body)"'
# for each blocker referenced, e.g.:
gh issue view <N> --json state -q .state   # CLOSED ?
```

## Outputs

When a PR passes all checks, swap the linked issue to ready and note it on the PR (swap, don't
accumulate — see workflow.md status invariants):

```bash
gh issue edit <TASK> --remove-label status:review-passed --add-label status:ready-to-merge
gh pr comment <PR> --body "Merge-ready: CI green, AI review passed, up to date with master. Awaiting human merge."
```

When **all** of a blocked task's blockers are closed, un-block it (returns it to the Groomer /
Implementer queue):

```bash
gh issue edit <TASK> --remove-label status:blocked
```

Leave it blocked if any blocker is still open.

## Guardrails

- **Never merge** and never bypass branch protection — a human clicks merge.
- Do not mark ready if any check is missing; when in doubt, leave it and note what's missing.
- Only un-block when **every** blocker is closed — never clear `status:blocked` speculatively.

## Stop conditions

Stop when no open PR can be marked ready and no blocked task can be un-blocked.
