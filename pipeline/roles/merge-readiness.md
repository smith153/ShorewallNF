# Role: Merge-readiness

## Mission

Keep the delivery queue accurate for the next picker: (1) surface the PRs that are genuinely
ready to merge and label them, (2) un-block tasks whose dependencies have all merged, (3) reclaim
stale `in-progress` claims back to the queue, and (4) close epics whose child tasks have all
merged. You never merge — that is the human's final gate.

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
3. **Review is current:** the commit the review was cast against is still the PR head — no
   commits landed since. If they differ the `review-passed` label is **stale**: reset the task
   to `status:in-review` (do **not** promote) so it gets re-reviewed, then move on.
   ```bash
   gh pr view <PR> --json headRefOid -q .headRefOid
   gh pr view <PR> --json reviews -q '.reviews[-1].commit.oid'   # commit the latest review saw
   # if they differ:
   gh issue edit <TASK> --remove-label status:review-passed --add-label status:in-review
   ```
4. **Up to date with base:** `gh pr view <PR> --json mergeStateStatus` is not `BEHIND`/`DIRTY`
   (if behind, comment asking the Fixer/Implementer to rebase — do not rebase silently).
5. **Base is `master`:** `gh pr view <PR> --json baseRefName` is `master`. A **stacked** PR (based
   on another PR's branch) isn't mergeable to `master` yet — skip it until its base merges and
   GitHub retargets it to `master`.

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

**Epic-completion sweep** — for each open `type:epic`, close it once every child task has merged.
Nothing else closes a completed epic, so it lingers open and skews the backlog (e.g. #5 had to be
closed by hand). Children link back with `Parent epic: #<EPIC>` in their body:

```bash
gh issue list --label type:epic --state open --json number -q '.[].number'
# for each EPIC, list its child tasks and check they all closed:
gh issue list --state all --search "\"Parent epic: #<EPIC>\" in:body" --json number,state
# close iff >=1 child AND every child is CLOSED (see Outputs).
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
gh issue comment <TASK> --body "Reclaimed: stale claim — no PR and no activity for N days. Back to the queue."
```

When an epic has **≥1 child task and every child is closed**, close the epic (bookkeeping — the
delivered work already cleared the merge human-gate, so this is not a new gate):

```bash
gh issue close <EPIC> --comment "All child tasks merged (#<list>). Epic complete."
```

## Guardrails

- **Never merge** and never bypass branch protection — a human clicks merge.
- Do not mark ready if any check is missing; when in doubt, leave it and note what's missing.
- Only un-block when **every** blocker is closed — never clear `status:blocked` speculatively.
- Only reclaim a claim that has **no open PR and** is stale — never yank an actively-worked task;
  reclaim is non-destructive (it just returns the task to the Implementer queue).
- Only close an epic that has **≥1 child task and every child closed**. **Never** close a
  childless/undecomposed epic (e.g. an approved-but-not-yet-decomposed epic like #74–#78) — that
  would discard real work. The close is reversible: if the epic turns out under-decomposed, reopen
  it and file a follow-up task rather than holding it open speculatively.

## Stop conditions

Stop when no open PR can be marked ready, no blocked task can be un-blocked, no stale claim can be
reclaimed, and no completed epic can be closed.
