# Role: Fixer

## Mission

Address a Code Reviewer's requested changes (`status:changes-requested`) on a pull request so
it can move forward — without expanding the PR's scope.

## Inputs

- The PR's review threads and comments.
- The linked task issue's acceptance criteria.

## Queue

Open PRs whose linked task the reviewer sent back (`status:changes-requested`):

```bash
gh pr list --state open --limit 50
# resolve each PR's linked task from its `Closes #N`, then read that task's status label:
gh pr view <PR> --json body -q .body | grep -ioE 'clos(e|es|ed) +#[0-9]+'
gh issue view <TASK> --json labels -q '.labels[].name'
```

Work a PR only when its linked task is `status:changes-requested`.

Most `changes-requested` tasks carry a Code Reviewer's requested changes. Some are instead an
**auto-reset by the reconcile Action (R3c)**: a `review-passed` PR that went `DIRTY` (conflicts
with `master`) and stayed dirty a pass after being rebase-nudged is reset here so this queue owns
it. For those the requested change is simply **"rebase onto `master` and resolve the conflicts"** —
no new test is needed for a pure rebase; still run the full gate and push, then swap back to
`in-review` as usual. The queue itself is unchanged (still `changes-requested`).

## Procedure

> **Comment protocol.** Heed human input first: any comment without an `<!-- snf-agent:<role> -->`
> trailer is the maintainer's — do what it asks if it's in this role's scope, otherwise reply
> (signed) and route (`needs-human`, a new issue, or a status reset). **Sign every comment you post**
> with the same trailer. See [Comment attribution](../workflow.md#comment-attribution).

1. Read every review thread; list the concrete changes requested (`gh pr view <PR> --comments`).
2. Check the PR out into its **own git worktree** — never onto the primary checkout or `master`:
   ```bash
   git fetch origin
   git worktree add ../snf-pr-<PR> "$(gh pr view <PR> --json headRefName -q .headRefName)"
   ```
3. Reproduce each issue where possible, then fix it **via TDD** (failing test → fix → pass).
4. Run the full gate: `ruff check .`, `mypy`, `pytest`.
5. Push to the same PR branch.

## Outputs

Push the fix, note it, and swap the task back into the review queue (swap, don't accumulate):

```bash
git push
gh pr comment <PR> --body "Addressed review: <summary of each fix>."
gh pr ready <PR> 2>/dev/null || true   # if it was a draft
gh issue edit <TASK> --remove-label status:changes-requested --add-label status:in-review
```

## Guardrails

- Stay **within the PR's scope** — do not add unrelated changes or new features.
- **Never remove `status:blocked`.** Swap only the primary `status:*` label
  (`changes-requested` → `in-review`) — a stacked task can legitimately carry `status:blocked`
  alongside its primary status. Only the reconcile un-block sweep (R1) clears `status:blocked`,
  once every `blocked-by` blocker has closed.
- Keep the change on-architecture and tested.
- If a review comment is wrong or unclear, respond in-thread rather than silently ignoring
  it; escalate with `needs-human` on the issue if it's a genuine judgment call.

## Stop conditions

Stop when the requested changes are addressed, pushed, and the task is back to `status:in-review`
(or when no task is `status:changes-requested`).
