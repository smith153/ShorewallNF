# Pipeline workflow

ShorewallNF is built by a pipeline of AI agents coordinated through GitHub. Work flows
through two phases: an upstream **Refinement** phase that grooms ideas into well-formed,
`implementation-ready` tasks, then a standard GitHub **Delivery** phase that turns tasks
into merged code.

Labels ([`labels.md`](labels.md)) describe an item's type/status; native GitHub state
(issues, PRs, CI) carries the rest. Review **verdicts** are the exception — a single shared
account can't cast `--approve`/`--request-changes` on its own PR, so review state rides on
`status:*` labels, not GitHub reviews.

## Roles

**Refinement**
1. **Epic Author** — surveys project state and proposes epics.
2. **Epic Decomposer** — breaks an approved epic into ordered, testable tasks.
3. **Task Groomer** — validates proposed tasks and gates them to `implementation-ready`.

**Delivery**
4. **Implementer** — implements one task via TDD and opens a PR.
5. **Code Reviewer** — reviews open PRs (cannot authorize merge).
6. **Fixer** — addresses requested changes on a PR.

The delivery-side **mechanical sweeps** (promote → `ready-to-merge`, un-block, reap stale claims,
reset stale reviews, nudge behind PRs to rebase) are run by the `pipeline-reconcile` GitHub Action
(see [Automation](#automation)), not a volunteer role; the former Merge-readiness role is kept as a
manual fallback ([`roles/merge-readiness.md`](roles/merge-readiness.md)).

## Lifecycle

```
Epic Author ─► epic:proposed ─►(human approve)─► Decomposer ─► task:proposed
     ─► Groomer ──(≤2 rounds)──► implementation-ready
     ─► Implementer (assignee + in-progress) ─► PR (Closes #N) ─► in-review
     ─► Code Reviewer ─► review-passed  (issues → changes-requested ⇄ Fixer → in-review)
     ─► reconcile Action (review-passed + green CI) ─► ready-to-merge ─►(human merge)─► closed
```

## Status transitions

| Status | Meaning | Applied by | Moves next when |
|--------|---------|------------|-----------------|
| `status:proposed` | Awaiting refinement/approval | Epic Author (epics), Decomposer (tasks) | Human approves epic / Groomer accepts task |
| `status:needs-refinement` | Groomer requested changes | Task Groomer | Decomposer/author revises → back to `proposed` |
| `status:implementation-ready` | Groomed & startable (epics: approved for decomposition) | Human (epics), Task Groomer (tasks) | Implementer claims it |
| `status:in-progress` | Claimed by an implementer | Implementer (with self-assign) | PR opened; or reclaimed to `implementation-ready` if the claim goes stale (reconcile Action) |
| `status:blocked` | Has unmet dependencies (`blocked-by`) | Decomposer/Groomer | All blockers closed → the reconcile Action un-block sweep clears it |
| `status:in-review` | Has an open PR awaiting (re-)review | Implementer / Fixer | Reviewer sets `review-passed` or `changes-requested` |
| `status:changes-requested` | Reviewer found blocking issues | Code Reviewer | Fixer pushes a fix → back to `in-review` |
| `status:review-passed` | AI review clean; awaiting human merge | Code Reviewer | the reconcile Action sets `ready-to-merge` (CI green, up to date, review still current); new commits → back to `in-review` |
| `status:ready-to-merge` | Approved + green; awaiting human merge | reconcile Action | Human merges |

## Status label invariants

- **One status at a time.** A task carries exactly one `status:*` label, optionally plus
  `status:blocked`. (An epic being decomposed is claimed by a transient `epic/<N>` git ref, not a
  label — see Collision avoidance.) Each role **swaps** the label — removing the prior status as it adds the
  next — rather than accumulating: claim = −`implementation-ready` +`in-progress`; PR opened =
  −`in-progress` +`in-review`; review clean = −`in-review` +`review-passed`; review found issues =
  −`in-review` +`changes-requested`; fix pushed = −`changes-requested` +`in-review`; commits after
  review = −`review-passed` +`in-review`; merge-ready = −`review-passed` +`ready-to-merge`. Merging
  closes the issue, so its final `status:*` is moot.
- **Un-blocking.** When a blocker's PR merges (its issue closes), the reconcile Action un-block
  sweep removes `status:blocked` from each dependent once **all** its `blocked-by` blockers are
  closed, returning it to the queue.

## Automation

The judgment-free transitions — un-blocking dependents, reaping stale claims, promoting
`review-passed`→`ready-to-merge`, resetting stale reviews, nudging behind PRs to rebase, and
flagging one-status-invariant violations — are run by the `pipeline-reconcile` GitHub Action
(`.github/workflows/reconcile.yml`, #106). It **replaces the delivery-side sweeps of the former
Merge-readiness role**, which is kept only as a manual fallback
([`roles/merge-readiness.md`](roles/merge-readiness.md)). It is an idempotent, **level-triggered**
reconcile: a cron pass guarantees liveness and the whole board is re-derived each run, so a missed
event self-heals. It ships **dry-run** (mutates only when the `RECONCILE_APPLY` repo variable is
`true`); enable it when you retire the manual role so the sweeps never pause. Its comments carry
the `snf-agent:reconcile` signature like any other role. Epic-closing is a considered judgment
(acceptance criteria, not just "all tasks closed"), so it stays with the Epic Author, not the
Action.

## Collision avoidance

Volunteers run agents concurrently (often overnight) on separate machines, so claiming must be
atomic on the **shared remote** — a local worktree or branch can't lock across machines:

- An agent **claims a task by atomically creating the ref `refs/heads/task/<N>`** on the remote
  (`gh api --method POST .../git/refs`) *before* doing any work. Creating a ref is atomic
  server-side: exactly one agent wins; the rest get `422 Reference already exists` and move on to
  another task. The branch is the bare issue number (`task/<N>`) so every agent computes the same
  ref for the same task.
- Only *after* winning the ref does the agent swap labels (`implementation-ready` → `in-progress`)
  and self-assign — that's human-visible status, **not** the lock (assignee can't be a lock under
  one shared account). Agents still only consider tasks that are `implementation-ready` and not
  `status:blocked`.
- A claim is released by **deleting the ref**: the Implementer on abort, or the reconcile Action when it
  reclaims a stale claim. (Enable *automatically delete head branches* so a merged `task/<N>` also
  frees the ref and can't cause a false `422` on a later re-claim.)
- The **Epic Decomposer** claims an epic the same way — atomically creating `refs/heads/epic/<N>`
  before decomposing it (a `422` means another Decomposer already has it) — and deletes the ref when
  done, so two decomposers can't duplicate the same epic.
- If two in-flight PRs would conflict (overlapping changes), the later one may be **stacked** —
  opened against the other's branch instead of `master` — rather than serialized or hand-merged.
  The reconcile Action holds a stacked PR (skips promoting it) until its base merges and GitHub retargets it to `master`.
- One task per PR; one PR per branch. **All code work happens in a per-task git worktree —
  never in the primary checkout or on `master`** (that isolation is what lets agents run
  concurrently).

## Comment attribution

Everyone — the maintainer and every agent — posts to GitHub as the same shared account, so a
comment's author can't tell human from agent. Agents make themselves identifiable instead:

- **Sign every comment.** Each agent comment on an issue or PR ends with the machine-readable
  trailer `<!-- snf-agent:<role> -->` (invisible when rendered) plus a visible `— <role> (agent)`.
- **Unsigned means human.** A comment without that trailer is the maintainer's.
- **Heed human input.** Before acting on an item, each role scans its comments; if any are
  unsigned and newer than that role's own last signed comment, the role must **either** do what
  they ask (when it is in the role's scope) **or** reply — signed — acknowledging it and route it
  (`needs-human`, a new issue, or a status reset). Never silently proceed past unaddressed human
  input.

A comment on an item no role will soon touch is only seen when a role next picks it up; flag such
items for a human if they need faster attention.

## Human gates

Only two human interventions are required; everything between them is autonomous.

1. **Epic approval (direction).** A human approves an epic by removing `status:proposed`
   and adding `status:implementation-ready` to the `type:epic` issue. The Decomposer only
   picks up epics in that approved state.
2. **Merge (final look).** Branch protection on `master` requires green CI **and** a human
   approving review (via [`CODEOWNERS`](../.github/CODEOWNERS)). The AI Code Reviewer never
   casts a GitHub review verdict — it signals its verdict with `status:*` labels — so it can
   never satisfy this gate.

## Escalation

The Refinement churn is bounded. The Task Groomer allows at most **2 rounds** of
request-changes on a task; if it still isn't right, the Groomer adds `needs-human` and
stops, leaving the decision to a maintainer. Any agent that is uncertain or blocked on a
judgment call should add `needs-human` rather than guess.
