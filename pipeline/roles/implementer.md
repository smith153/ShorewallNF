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

**Claiming a blocked task to stack it (bounded exception).** The queue excludes `status:blocked`
because an unmet dependency is not a stable foundation. You MAY still claim a `status:blocked` task
**to stack it** — but only when **every open `blocked-by` blocker is already `status:review-passed`
or `status:ready-to-merge`** (approved, awaiting only the human merge). Base the PR on the blocker's
`task/<N>` branch (not `master`) and **keep `status:blocked`** (swap only the primary `status:*` —
see Guardrails; the reconcile un-block sweep clears `status:blocked` once the blocker closes).
Claiming a `status:blocked` task whose blocker is **not yet approved** remains a violation.

## Procedure

> **Comment protocol.** Heed human input first: any comment without an `<!-- snf-agent:<role> -->`
> trailer is the maintainer's — do what it asks if it's in this role's scope, otherwise reply
> (signed) and route (`needs-human`, a new issue, or a status reset). **Sign every comment you post**
> with the same trailer. See [Comment attribution](../workflow.md#comment-attribution).

1. **Claim atomically on the remote** — create the claim ref *before* any work; the bare issue
   number makes every agent compute the same ref, and ref creation is atomic server-side:
   ```bash
   sha="$(gh api repos/{owner}/{repo}/git/ref/heads/master -q .object.sha)"
   gh api --method POST repos/{owner}/{repo}/git/refs -f ref=refs/heads/task/<TASK> -f sha="$sha"
   ```
   A **`422` (Reference already exists)** means another agent claimed it — skip to the next task.
   On success you own it; now record human-visible status (not the lock):
   ```bash
   gh issue edit <TASK> --add-assignee @me --add-label status:in-progress --remove-label status:implementation-ready
   ```
2. Work in a **dedicated git worktree** tracking the claimed branch — never the primary checkout or
   `master` (agent runtimes with worktree tooling do this for you):
   ```bash
   git fetch origin && git worktree add ../snf-task-<TASK> task/<TASK>
   ```
3. **TDD:** write a failing test → run it, confirm it fails → minimal implementation →
   run tests, confirm pass. Repeat per acceptance criterion.
4. Keep the change on-architecture (Reader → Parser → IR → Validator → Generator → Applier).
5. Run the full gate locally: `ruff check .`, `mypy`, `pytest`.

## Outputs

Open a PR that auto-closes the issue and mark it in-review:

```bash
git push
gh pr create --fill --title "<goal>" --body "Closes #<TASK>

## How it was tested
<tests added; nft -c clean; netns if applicable>"
gh issue edit <TASK> --remove-label status:in-progress --add-label status:in-review
```

**Stack instead of stalling.** Open your PR **against another `task/<N>` branch** instead of
`master` — a "stacked" PR that shows only your diff and merges cleanly — for either reason: your
change would **conflict with another open PR** (overlapping files), **or** you are keeping delivery
flowing while the human merge gate is closed (e.g. overnight) by building a dependent task on its
approved blocker's not-yet-merged branch (per the bounded claim exception above). The "stacked"
signal is the **PR base branch** (`base_ref != "master"`) — no new label:

```bash
gh pr create --base <blocker-or-other-branch> --fill --title "<goal>" --body "Closes #<TASK> ..."
```

Once the base PR merges, GitHub retargets yours to `master` (when the base branch is deleted);
rebase if needed. Prefer this over hand-resolving conflicts or forcing the work to serialize.

## Guardrails

- **One task per PR**; one PR per branch. Never commit to `master`. Target `master` — unless you are
  stacking (to avoid a conflict, or to keep flow on an approved blocker), in which case base it on
  that `task/<N>` branch (Outputs).
- Tests are required (TDD) — no implementation without a failing test first.
- **Never remove `status:blocked`.** Swap only the primary `status:*` label (e.g.
  `implementation-ready` → `in-progress`, `in-progress` → `in-review`) — a stacked task can
  legitimately carry `status:blocked` alongside its primary status. Only the reconcile un-block
  sweep (R1) clears `status:blocked`, once every `blocked-by` blocker has closed.
- Respect the Global Constraints in the plan/CLAUDE.md (Python ≥3.11, type hints, minimal deps).
- Follow the **code philosophy** ([CLAUDE.md](../../CLAUDE.md)): YAGNI (no speculative code),
  fail-fast with a clear error over defensive `if`s, and brief comments/PR summaries.
- If the task turns out to be wrong or blocked, stop, **delete your claim ref** to release it, and
  add `needs-human` with an explanation:
  ```bash
  gh api --method DELETE repos/{owner}/{repo}/git/refs/heads/task/<TASK>
  ```

## Stop conditions

Stop when the PR is opened, or when there are no unassigned, ready, unblocked tasks.
