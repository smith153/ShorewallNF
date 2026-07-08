# Role: Merge-readiness

## Mission

> **Fallback runbook — not an active session role.** These sweeps are run automatically by the
> `pipeline-reconcile` GitHub Action (`.github/workflows/reconcile.yml`, #106). Run this by hand
> only when the Action is disabled or broken. Epic-closing moved to the
> [Epic Author](epic-author.md).

Keep the delivery queue accurate for the next picker: (1) surface the PRs that are genuinely
ready to merge and label them, (2) un-block tasks whose dependencies have all merged, and (3)
reclaim stale `in-progress` claims back to the queue. You never merge — that is the human's final
gate.

## Inputs

- Open PRs, their CI status, the linked task's `status:review-passed` label, and merge state
  (up to date with `master`?).
- Open issues carrying `status:blocked` and their `blocked-by` references.
- Open issues carrying `status:in-progress` (to spot and reclaim abandoned claims).

## Queue

```bash
gh pr list --state open --limit 100
gh issue list --label status:blocked --state open --limit 100
gh issue list --label status:in-progress --state open --limit 100
```

## Procedure

> **Comment protocol.** Heed human input first: any comment without an `<!-- snf-agent:<role> -->`
> trailer is the maintainer's — do what it asks if it's in this role's scope, otherwise reply
> (signed) and route (`needs-human`, a new issue, or a status reset). **Sign every comment you post**
> with the same trailer. See [Comment attribution](../workflow.md#comment-attribution).

**Merge-ready check** — for each open PR, verify all of:

1. **CI green:** `gh pr checks <PR>` all passing.
2. **AI review passed:** the linked task carries `status:review-passed` (the Code Reviewer's
   clean verdict rides on the label, not a GitHub review — see [`workflow.md`](../workflow.md)).
   ```bash
   gh pr view <PR> --json body -q .body | grep -ioE 'clos(e|es|ed) +#[0-9]+'   # the linked task
   gh issue view <TASK> --json labels -q '.labels[].name'   # expect status:review-passed
   ```
3. **Review is current:** the latest review was cast at or after the current head commit — no
   commits landed since. `gh` exposes **no per-review commit**, so compare timestamps: the
   latest review's `submittedAt` vs. the head commit's `committedDate`. If the head is newer the
   `review-passed` label is **stale**: reset the task to `status:in-review` (do **not** promote)
   so it gets re-reviewed, then move on.
   ```bash
   gh pr view <PR> --json commits -q '.commits[-1].committedDate'   # head commit time
   gh pr view <PR> --json reviews -q '.reviews[-1].submittedAt'     # latest review time
   # if the head commit is newer than the latest review:
   gh issue edit <TASK> --remove-label status:review-passed --add-label status:in-review
   ```
4. **Up to date with base:** `gh pr view <PR> --json mergeStateStatus` is not `BEHIND`/`DIRTY`
   (if behind, comment asking the Fixer/Implementer to rebase — do not rebase silently).
5. **Base is `master`:** `gh pr view <PR> --json baseRefName` is `master`. A **stacked** PR (based
   on another PR's branch) isn't mergeable to `master` yet — skip it until its base merges and
   GitHub retargets it to `master`.

**Batch test-merge gate** — _automated by the Action (#247)._ When a reconcile pass finds **2+**
promote-eligible PRs it now test-merges their branches together onto the current `origin/master`
tip (each merge committed before the next), runs `ruff`/`mypy`/`pytest` on the combined tree, and
promotes to `status:ready-to-merge` **only** if the whole batch is green — otherwise it holds the
batch at `status:review-passed` and posts a signed flag (adding `needs-human` on a red merged gate).
A lone promote-eligible PR skips the test-merge and promotes as before. The pure candidate selection
and the promote/hold action sets live in `scripts/reconcile/core.py`; the git merge + gate execution
is the shell (`scripts/reconcile/run.py`). **Run the steps below by hand only when the Action is
disabled or broken.**

The checks above vet each PR *in isolation*, but two independently-green PRs can still break
`master` when merged **together**: a symbol renamed in one vs. its caller in another (#173/#174), a
hardcoded CI count-guard vs. a newly-added test (#183/#199), or several PRs appending to the same
file tail (#205/#208/#209). Per-PR CI never sees the interaction. So before promoting **more than
one** PR in a single sweep (or handing a batch to the human), test-merge the `review-passed`
branches together onto the **current master tip** (`origin/master`) and run the full gate:

```bash
git fetch origin
git worktree add ../snf-merge-check origin/master
cd ../snf-merge-check
for br in <branch-1> <branch-2> …; do            # in the intended merge order
  git merge --no-edit "origin/$br" || { echo "CONFLICT at $br"; break; }
done
python -m ruff check . && python -m mypy && python -m pytest -q
```

Commit each merge before the next — a chained `git merge --no-commit` leaves a stray `MERGE_HEAD`
that looks like a false conflict. If the batch conflicts or the merged gate is red, **do not promote
the whole batch**:

- **Additive same-file conflicts** (several PRs each appending a new CLI verb, a `KNOWN_CONFIG_FILES`
  entry, or a test at a file tail) — resolve by rebasing the PRs into a linear **stack** in a chosen
  order (union resolution) and force-pushing, so the human merges them in sequence with zero conflict
  clicks. Re-target each stacked PR's base onto its predecessor's branch (`gh` PR base); GitHub
  retargets to `master` as each base merges. This repo uses **merge commits**, so the stacked bases
  become `master` ancestors and merge cleanly.
- **Semantic breakage** (a rename vs. its caller, a guard vs. a new test) — leave the interacting PRs
  `status:review-passed` (don't promote), flag the interaction on each PR (signed), and add
  `needs-human` if it needs a human decision.

Promote to `status:ready-to-merge` only the PRs that survive the batch test-merge together; a lone
ready PR needs no batch check. Delete the throwaway worktree afterwards (`git worktree remove`).

**Un-block sweep** — for each open issue with `status:blocked`, read its `blocked-by #N`
references and check whether every referenced blocker is closed:

```bash
gh issue list --label status:blocked --state open --json number,body \
  -q '.[] | "#\(.number)\t\(.body)"'
# for each blocker referenced, e.g.:
gh issue view <N> --json state -q .state   # CLOSED ?
```

**Stale-claim sweep** — for each open issue with `status:in-progress`, reclaim abandoned claims
so they don't stall forever. A claim is stale when it has **no open PR** *and* the issue hasn't
been touched in **N days** (default 2 — tune here):

```bash
gh issue list --label status:in-progress --state open --json number,updatedAt,assignees \
  -q '.[] | "#\(.number)\t\(.updatedAt)\t\(.assignees|map(.login)|join(","))"'
# for each: skip if a PR already closes it; else if updatedAt is older than N days, reclaim it.
gh pr list --state open --search "<TASK> in:body"   # any open PR for this task? -> skip
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

When a claim is stale (no open PR **and** untouched for N days), reclaim it to the queue and say
why (swap, don't accumulate):

```bash
gh issue edit <TASK> --remove-assignee <assignee> \
  --remove-label status:in-progress --add-label status:implementation-ready
gh api --method DELETE repos/{owner}/{repo}/git/refs/heads/task/<TASK>   # release the claim ref
gh issue comment <TASK> --body "Reclaimed: stale claim — no PR and no activity for N days. Back to the queue."
```

## Guardrails

- **Never merge** and never bypass branch protection — a human clicks merge.
- **Don't hand off an untested batch.** When 2+ PRs are ready in one sweep, run the Batch
  test-merge gate first and promote only what survives it together — each PR's isolated CI does not
  guarantee they compose.
- Do not mark ready if any check is missing; when in doubt, leave it and note what's missing.
- Only un-block when **every** blocker is closed — never clear `status:blocked` speculatively.
- Only reclaim a claim that has **no open PR and** is stale — never yank an actively-worked task;
  reclaim is non-destructive (it just returns the task to the Implementer queue). Reclaiming also
  **deletes the `task/<N>` claim ref** so the task can be re-claimed.

## Stop conditions

Stop when no open PR can be marked ready, no blocked task can be un-blocked, and no stale claim
can be reclaimed. A ready batch that fails the Batch test-merge gate is **not safe to hand off** —
leave the interacting PRs `status:review-passed` (stacked or flagged), don't promote them, and note
why; that is a stop, not a promotion.
