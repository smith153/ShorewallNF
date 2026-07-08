"""Pure transition rules for the reconcile Action (issue #106).

Functional core (ADR-0003): given a board snapshot, decide the label / assignee / ref /
comment actions that drive every issue and PR to its correct pipeline state. No I/O — the
shell (:mod:`reconcile.run`) gathers the snapshot via ``gh`` and applies the returned
actions. Every rule is *idempotent*: it changes the state it triggers on (or is gated by a
one-shot flag), so a second pass over the resulting board emits nothing.

The rules mirror the judgment-free half of pipeline/roles/merge-readiness.md:

* **R1 un-block** — clear ``status:blocked`` once every blocker closed *as completed*; a
  ``NOT_PLANNED`` blocker escalates (``needs-human``) instead of silently releasing.
* **R2 stale-claim reap** — return an abandoned ``in-progress`` claim to the queue and free
  its ``task/<N>`` ref.
* **R3 ready-to-merge** — promote a ``review-passed`` PR that is green, current and on master.
* **R3b rebase-nudge** — a green + current ``review-passed`` PR that is ``BEHIND`` or
  ``CONFLICTING`` (not up to date) gets a one-per-head "please rebase" nudge instead of promoting.
* **R3c conflict-escalation** — a ``review-passed`` PR that is a *true conflict* (``CONFLICTING``)
  **and** has already been rebase-nudged for its current head (a rebase-in-place didn't clear it)
  is reset ``review-passed`` → ``changes-requested`` so the Fixer owns the rebase/resolution. Only
  a persistent ``CONFLICTING`` escalates — a plain ``BEHIND`` only ever gets the R3b nudge.
* **R4 review-freshness** — reset a ``review-passed`` PR whose current head oid no longer
  equals the commit oid the latest review was cast against (``reviews(last:1).commit.oid`` via
  GraphQL) — an exact "review pins to this commit" check, not a timestamp proxy.
* **R5 one-status invariant** — drive every issue to exactly one primary ``status:*`` label.
  A lingering *pre-review claim* status (``implementation-ready``/``in-progress``) that a
  strictly-later primary supersedes is stripped (**self-heal**, #227) — the #195/#219 silent
  merge-gate stall; ``needs-human`` is flagged only for a genuinely ambiguous double-primary
  self-heal can't resolve. ``status:blocked`` is an orthogonal modifier that legitimately
  coexists (#146) and is never stripped.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

#: Environment names the batch-gate subprocess is allowed to inherit, plus the prefixes
#: :func:`gate_env` also keeps (``LC_*`` locale categories; ``PYTHON*`` interpreter tuning like
#: ``PYTHONPATH``). Everything else is dropped — a default-deny allow-list, not a deny-list — so
#: the merged, *unreviewed* contributor code the gate executes can read only what ruff/mypy/
#: pytest need, never a runner credential (``GITHUB_*``, ``ACTIONS_*``, ``*_TOKEN``, ``*_SECRET``).
GATE_ENV_ALLOW = frozenset(
    {"PATH", "HOME", "LANG", "TZ", "TMPDIR", "VIRTUAL_ENV", "CI"}
)
GATE_ENV_ALLOW_PREFIXES = ("LC_", "PYTHON")


def gate_env(environ: Mapping[str, str]) -> dict[str, str]:
    """The scrubbed environment for the batch-gate subprocess: ``environ`` filtered to the
    :data:`GATE_ENV_ALLOW` names and :data:`GATE_ENV_ALLOW_PREFIXES` prefixes only (default-deny).

    Pure (data-in → data-out, no I/O) so it can be unit-tested over a synthetic dict without
    spawning a process — the shell passes it the real ``os.environ``. Filtering by name never
    invents an absent key, so only variables actually present survive.

    This closes the gate child's *own* environment as a credential source. It does **not** close
    the parent-process gap: on a privileged run the reconcile job's write-scoped token still lives
    in the parent, recoverable from ``/proc/<ppid>/environ`` by same-UID child code — tracked
    separately as #280.
    """
    return {
        k: v
        for k, v in environ.items()
        if k in GATE_ENV_ALLOW or k.startswith(GATE_ENV_ALLOW_PREFIXES)
    }

#: The mutually-exclusive primary pipeline states. ``status:blocked`` is an allowed
#: *accumulation* on top of one of these; ``status:decomposing`` is retired (epics are now
#: claimed by an ``epic/<N>`` ref — see pipeline/workflow.md).
PRIMARY_STATUS = frozenset(
    {
        "status:proposed",
        "status:needs-refinement",
        "status:implementation-ready",
        "status:in-progress",
        "status:in-review",
        "status:changes-requested",
        "status:review-passed",
        "status:ready-to-merge",
    }
)

BLOCKED = "status:blocked"
NEEDS_HUMAN = "needs-human"

#: Pipeline progression of the primary statuses (index = lifecycle position). Used only by the
#: R5 self-heal to tell whether a lingering pre-review claim label has been superseded by a
#: strictly-later primary. Only the *ordering of the two claim statuses before every later
#: state* is load-bearing — the exact order among the post-review states is not.
_STATUS_ORDER: dict[str, int] = {
    "status:proposed": 0,
    "status:needs-refinement": 1,
    "status:implementation-ready": 2,
    "status:in-progress": 3,
    "status:in-review": 4,
    "status:changes-requested": 5,
    "status:review-passed": 6,
    "status:ready-to-merge": 7,
}

#: Pre-review "claim" statuses the Implementer/Reviewer swap should have removed. When one
#: lingers alongside a strictly-later primary — the #195/#219 stall — reconcile strips it
#: (self-heal) instead of flagging needs-human. ``status:blocked`` is deliberately NOT here:
#: it is an orthogonal modifier that legitimately coexists (#146) and is never self-healed.
STALE_CLAIM_STATUSES = frozenset({"status:implementation-ready", "status:in-progress"})

#: Machine-readable signature so the maintainer's "unsigned == human" rule (pipeline/
#: workflow.md#comment-attribution) still holds for comments this Action posts.
AGENT_SIGN = "<!-- snf-agent:reconcile -->"

#: Extra tag on the "please rebase" nudge so the shell can dedupe it (one per stale head),
#: since a behind-base PR stays behind across runs and a plain comment would repeat every cron.
REBASE_TAG = "<!-- snf-agent:reconcile:rebase -->"


class BlockerState(Enum):
    """Closed-state of a referenced blocker issue."""

    OPEN = "open"
    COMPLETED = "completed"  # closed as completed — the blocker was delivered
    NOT_PLANNED = "not_planned"  # closed as not planned — do NOT release dependents


class Mergeability(Enum):
    """A PR's standing relative to its base — the R3 promote gate.

    The shell derives this from ``mergeStateStatus``. Only ``READY`` may promote. ``BEHIND`` and
    ``CONFLICTING`` both earn a rebase nudge (R3b); they are kept distinct so R3c can escalate a
    *persistent* ``CONFLICTING`` (a true content conflict a rebase-in-place hasn't cleared) to the
    Fixer, while a plain ``BEHIND`` is only ever nudged. ``PENDING`` (mergeability not computed
    yet, or a draft) is *indeterminate* — skipped silently and re-checked next run, so a
    not-yet-computed state can never masquerade as "behind" and trigger a false nudge.
    """

    READY = "ready"  # up to date (CLEAN / BLOCKED-on-review / UNSTABLE / HAS_HOOKS…) — promotable
    BEHIND = "behind"  # BEHIND base — cleanly behind; nudge to rebase (R3b), never escalate
    CONFLICTING = "conflicting"  # DIRTY — true conflict; nudge, then escalate on persistence (R3c)
    PENDING = "pending"  # UNKNOWN (not computed) or DRAFT — indeterminate; skip, re-check


class ActionKind(Enum):
    ADD_LABEL = "add_label"
    REMOVE_LABEL = "remove_label"
    UNASSIGN = "unassign"
    COMMENT = "comment"
    DELETE_REF = "delete_ref"


@dataclass(frozen=True)
class Action:
    """One primitive mutation the shell applies (or logs, in dry-run)."""

    kind: ActionKind
    number: int  # issue or PR number the action targets
    value: str = ""  # label name / assignee login / comment body / ref name
    on_pr: bool = False  # COMMENT target is a PR (labels/assignees are issues only)
    reason: str = ""  # human-readable why, for dry-run logs


@dataclass(frozen=True)
class Issue:
    number: int
    labels: frozenset[str]
    updated_at: datetime
    assignees: tuple[str, ...] = ()
    blocked_by: tuple[int, ...] = ()
    has_open_pr: bool = False
    is_epic: bool = False


@dataclass(frozen=True)
class PullRequest:
    number: int
    task: int | None
    base_ref: str
    ci_green: bool
    mergeability: Mergeability  # standing vs. base — READY / BEHIND / CONFLICTING / PENDING
    head_oid: str  # current PR head commit oid
    reviewed_oid: str | None  # commit oid the latest review was cast against (None if no review)
    #: whether a rebase nudge already exists for the *current* head (the R3c persistence signal):
    #: a conflict that is still dirty a pass after we asked for a rebase escalates to the Fixer.
    rebase_nudged: bool = False


@dataclass(frozen=True)
class Board:
    issues: tuple[Issue, ...]
    pulls: tuple[PullRequest, ...] = ()
    #: state of every issue referenced as a blocker (a still-open blocker is ``OPEN``)
    blocker_state: dict[int, BlockerState] = field(default_factory=dict)


def _sign(body: str) -> str:
    return f"{body}\n\n— reconcile (agent)\n{AGENT_SIGN}"


def _primaries(issue: Issue) -> frozenset[str]:
    return issue.labels & PRIMARY_STATUS


def _has_status(issue: Issue) -> bool:
    return any(label.startswith("status:") for label in issue.labels)


def _review_current(pr: PullRequest) -> bool:
    """True iff the latest review was cast against the current head commit — i.e. its reviewed
    oid equals the PR head oid. No review (``reviewed_oid is None``) is not current."""
    return pr.reviewed_oid is not None and pr.reviewed_oid == pr.head_oid


def _superseded_stale(issue: Issue) -> frozenset[str]:
    """Pre-review claim labels on ``issue`` a strictly-later primary status supersedes — the
    R5 self-heal set. Empty unless a claim status lingers under a genuinely later one."""
    primaries = _primaries(issue)
    latest = max((_STATUS_ORDER[p] for p in primaries), default=-1)
    return frozenset(
        p for p in primaries if p in STALE_CLAIM_STATUSES and _STATUS_ORDER[p] < latest
    )


def _self_heal_stale(
    issues: tuple[Issue, ...],
) -> tuple[list[Action], dict[int, frozenset[str]]]:
    """Strip stale claim statuses superseded by a later primary (R5 self-heal, #227). Returns
    the removal (+ signed reason) actions and each issue's primaries *after* healing, so the
    one-status flag sees the corrected set and escalates only a genuinely ambiguous remainder.
    A human's ``needs-human`` is respected (like unblock/reap) — such an issue is left untouched."""
    actions: list[Action] = []
    healed: dict[int, frozenset[str]] = {}
    for issue in issues:
        stale = frozenset() if NEEDS_HUMAN in issue.labels else _superseded_stale(issue)
        healed[issue.number] = _primaries(issue) - stale
        if not stale:
            continue
        dropped = ", ".join(f"`{s}`" for s in sorted(stale))
        actions += [
            Action(ActionKind.REMOVE_LABEL, issue.number, s, reason="stale-status")
            for s in sorted(stale)
        ]
        actions.append(
            Action(
                ActionKind.COMMENT,
                issue.number,
                _sign(
                    f"Self-healing the one-status invariant: removed the stale {dropped}, "
                    "superseded by a later primary status (a transition left the claim label "
                    "behind). No human needed."
                ),
                reason="stale-status",
            )
        )
    return actions, healed


def _invariant_violators(
    issues: tuple[Issue, ...], healed_primaries: dict[int, frozenset[str]]
) -> set[int]:
    """Issues carrying some ``status:*`` label but not exactly one *primary* status, judged on
    the post-self-heal primary set so a healed stale claim is no longer a violation."""
    return {i.number for i in issues if _has_status(i) and len(healed_primaries[i.number]) != 1}


def _flag_invariant(
    issues: tuple[Issue, ...],
    violators: set[int],
    healed_primaries: dict[int, frozenset[str]],
) -> list[Action]:
    actions: list[Action] = []
    for issue in issues:
        if issue.number not in violators or NEEDS_HUMAN in issue.labels:
            continue  # healthy, or already escalated (one-shot — no comment spam)
        found = ", ".join(sorted(healed_primaries[issue.number])) or "none"
        actions += [
            Action(ActionKind.ADD_LABEL, issue.number, NEEDS_HUMAN, reason="invariant"),
            Action(
                ActionKind.COMMENT,
                issue.number,
                _sign(
                    "Invariant violation: an issue must carry exactly one primary "
                    f"`status:*` label, but this one has: {found}. Flagging for a human."
                ),
                reason="invariant",
            ),
        ]
    return actions


def _unblock(
    issues: tuple[Issue, ...], blocker_state: dict[int, BlockerState], skip: set[int]
) -> list[Action]:
    actions: list[Action] = []
    for issue in issues:
        if issue.number in skip or BLOCKED not in issue.labels or not issue.blocked_by:
            continue
        if NEEDS_HUMAN in issue.labels:
            continue  # already escalated
        states = [blocker_state.get(b, BlockerState.OPEN) for b in issue.blocked_by]
        if any(s is BlockerState.OPEN for s in states):
            continue  # still genuinely blocked
        if any(s is BlockerState.NOT_PLANNED for s in states):
            rejected = ", ".join(
                f"#{b}"
                for b, s in zip(issue.blocked_by, states, strict=True)
                if s is BlockerState.NOT_PLANNED
            )
            actions += [
                Action(ActionKind.ADD_LABEL, issue.number, NEEDS_HUMAN, reason="blocker-rejected"),
                Action(
                    ActionKind.COMMENT,
                    issue.number,
                    _sign(
                        f"Blocker {rejected} was closed as *not planned*, so this task's "
                        "foundation was rejected rather than delivered. Not auto-unblocking — "
                        "a human should decide whether it is still valid."
                    ),
                    reason="blocker-rejected",
                ),
            ]
            continue
        actions += [
            Action(ActionKind.REMOVE_LABEL, issue.number, BLOCKED, reason="unblock"),
            Action(
                ActionKind.COMMENT,
                issue.number,
                _sign("Un-blocked: every `blocked-by` blocker has merged. Back to the queue."),
                reason="unblock",
            ),
        ]
    return actions


def _reap_stale(
    issues: tuple[Issue, ...], now: datetime, stale_after: timedelta, skip: set[int]
) -> list[Action]:
    actions: list[Action] = []
    for issue in issues:
        if issue.number in skip or "status:in-progress" not in issue.labels:
            continue
        if issue.has_open_pr or now - issue.updated_at <= stale_after:
            continue
        actions.append(
            Action(
                ActionKind.REMOVE_LABEL, issue.number, "status:in-progress", reason="stale-claim"
            )
        )
        actions.append(
            Action(
                ActionKind.ADD_LABEL,
                issue.number,
                "status:implementation-ready",
                reason="stale-claim",
            )
        )
        for login in issue.assignees:
            actions.append(Action(ActionKind.UNASSIGN, issue.number, login, reason="stale-claim"))
        actions.append(
            Action(
                ActionKind.DELETE_REF, issue.number, f"task/{issue.number}", reason="stale-claim"
            )
        )
        actions.append(
            Action(
                ActionKind.COMMENT,
                issue.number,
                _sign(
                    "Reclaimed: stale claim — no open PR and no activity for the reap window. "
                    "Claim ref released; back to the implementer queue."
                ),
                reason="stale-claim",
            )
        )
    return actions


def _promote(task_number: int, pr_number: int) -> list[Action]:
    """The R3 promote action triple: swap review-passed → ready-to-merge + a signed PR note."""
    return [
        Action(ActionKind.REMOVE_LABEL, task_number, "status:review-passed", reason="ready"),
        Action(ActionKind.ADD_LABEL, task_number, "status:ready-to-merge", reason="ready"),
        Action(
            ActionKind.COMMENT,
            pr_number,
            _sign(
                "Merge-ready: CI green, AI review passed and current, up to date with "
                "master. Awaiting human merge."
            ),
            on_pr=True,
            reason="ready",
        ),
    ]


def _promote_and_refresh(board: Board, skip: set[int], batch_deferred: set[int]) -> list[Action]:
    by_number = {i.number: i for i in board.issues}
    actions: list[Action] = []
    for pr in board.pulls:
        if pr.task is None or pr.task in skip:
            continue
        task = by_number.get(pr.task)
        if task is None or "status:review-passed" not in task.labels:
            continue
        if not _review_current(pr):
            # R4: head oid no longer matches the reviewed oid (or no review) — reset.
            actions += [
                Action(
                    ActionKind.REMOVE_LABEL, task.number, "status:review-passed", reason="freshness"
                ),
                Action(ActionKind.ADD_LABEL, task.number, "status:in-review", reason="freshness"),
                Action(
                    ActionKind.COMMENT,
                    pr.number,
                    _sign(
                        "Review is stale: the current head differs from the reviewed commit, "
                        "so resetting to `status:in-review` for re-review."
                    ),
                    on_pr=True,
                    reason="freshness",
                ),
            ]
            continue
        # Review is current. A still-blocked task never advances past review, even when its PR
        # is green/current/on-master/mergeable: R1 (un-block) is the sole remover of
        # status:blocked, so hold here until it clears (#146).
        if BLOCKED in task.labels:
            continue
        # A stacked PR (base ≠ master) is held until it retargets; a red PR isn't ready — skip
        # both silently.
        if pr.base_ref != "master" or not pr.ci_green:
            continue
        if pr.mergeability is Mergeability.CONFLICTING and pr.rebase_nudged:
            # R3c: a *true conflict* (DIRTY) that's already been rebase-nudged for this exact
            # head — a rebase-in-place hasn't cleared it, so hand it to the Fixer: swap the
            # primary status review-passed → changes-requested (leaving status:blocked, if
            # present, intact per #146 — though a blocked task is already held above). Idempotent:
            # once changes-requested, _promote_and_refresh no longer touches it.
            actions += [
                Action(
                    ActionKind.REMOVE_LABEL,
                    task.number,
                    "status:review-passed",
                    reason="conflict",
                ),
                Action(
                    ActionKind.ADD_LABEL,
                    task.number,
                    "status:changes-requested",
                    reason="conflict",
                ),
                Action(
                    ActionKind.COMMENT,
                    pr.number,
                    _sign(
                        "This branch conflicts with `master` and the rebase nudge for its current "
                        "head went unaddressed, so it can't be promoted. Resetting to "
                        "`status:changes-requested` and handing it to the Fixer to rebase onto "
                        "`master` and resolve the conflicts. (CI green, AI review passed.)"
                    ),
                    on_pr=True,
                    reason="conflict",
                ),
            ]
            continue
        if pr.mergeability in (Mergeability.BEHIND, Mergeability.CONFLICTING):
            # R3b: green + current but behind base, or a *first-observed* conflict — nudge to
            # rebase instead of promoting (the shell dedupes this so it fires once per stale
            # head, not every run). A persistent conflict escalates above (R3c); a plain BEHIND
            # is only ever nudged.
            actions.append(
                Action(
                    ActionKind.COMMENT,
                    pr.number,
                    f"{REBASE_TAG}\n"
                    + _sign(
                        "This PR isn't up to date with `master` (behind or conflicting), so it "
                        "can't be marked merge-ready yet — please rebase/update the branch. "
                        "(CI green, AI review passed.)"
                    ),
                    on_pr=True,
                    reason="rebase",
                )
            )
            continue
        if pr.mergeability is not Mergeability.READY:
            # PENDING: mergeability not computed yet (or draft) — don't promote and don't
            # mistake it for "behind". Re-checked next run once GitHub settles it.
            continue
        # R3: green, current, up to date, on master — promotable. But when 2+ PRs are
        # promotable in one pass (#247), the promotion is deferred to the shell's batch
        # test-merge gate: it merges the candidate branches together onto the current master
        # tip and re-runs ruff/mypy/pytest, so a pair that breaks only when combined (a rename
        # vs. its caller, a guard vs. a new test) is caught before either is promoted. A lone
        # candidate has nothing to compose with and promotes inline exactly as before.
        if pr.number in batch_deferred:
            continue
        actions += _promote(task.number, pr.number)
    return actions


def _is_promotable(pr: PullRequest, task: Issue) -> bool:
    """The full R3 promote gate for one PR: review-passed, review-current, not blocked, based on
    master, CI green, and up to date (``READY``). This is exactly the condition under which
    :func:`_promote_and_refresh` would promote — factored out so candidate *selection* (the batch
    to test-merge) and the inline promote decision can never diverge."""
    return (
        "status:review-passed" in task.labels
        and _review_current(pr)
        and BLOCKED not in task.labels
        and pr.base_ref == "master"
        and pr.ci_green
        and pr.mergeability is Mergeability.READY
    )


def select_promotion_candidates(board: Board, skip: set[int]) -> list[PullRequest]:
    """Every PR that individually passes the R3 promote gate, ordered by PR number (a stable,
    deterministic test-merge order). Pure — no git/test I/O."""
    by_number = {i.number: i for i in board.issues}
    out: list[PullRequest] = []
    for pr in board.pulls:
        if pr.task is None or pr.task in skip:
            continue
        task = by_number.get(pr.task)
        if task is not None and _is_promotable(pr, task):
            out.append(pr)
    return sorted(out, key=lambda pr: pr.number)


def batch_candidates(board: Board) -> list[PullRequest]:
    """The promote-eligible PRs that must be test-merged **together** before any is promoted —
    i.e. the R3 candidates when 2+ are eligible in one pass. A batch of 0 or 1 returns ``[]``
    (those promote inline via :func:`reconcile`; a lone PR has nothing to compose with).

    Uses the same skip set (self-heal / invariant normalization) as :func:`reconcile`, so the
    batch and the inline-deferral decision are computed from one source of truth."""
    _, _, _, skip = _normalize(board)
    candidates = select_promotion_candidates(board, skip)
    return candidates if len(candidates) >= 2 else []


def batch_promote_actions(candidates: list[PullRequest], board: Board) -> list[Action]:
    """Promote every batch member that survived the joint test-merge (all of them, since the
    gate is all-or-nothing). Same label swap as the inline R3 promote, with a batch-aware note."""
    by_number = {i.number: i for i in board.issues}
    n = len(candidates)
    actions: list[Action] = []
    for pr in candidates:
        if pr.task is None or pr.task not in by_number:
            continue
        actions += [
            Action(
                ActionKind.REMOVE_LABEL, pr.task, "status:review-passed", reason="batch-ready"
            ),
            Action(ActionKind.ADD_LABEL, pr.task, "status:ready-to-merge", reason="batch-ready"),
            Action(
                ActionKind.COMMENT,
                pr.number,
                _sign(
                    f"Merge-ready: CI green, AI review passed and current, up to date with "
                    f"master, and this batch of {n} promote-eligible PRs test-merged together "
                    f"onto the current master tip with a green gate. Awaiting human merge."
                ),
                on_pr=True,
                reason="batch-ready",
            ),
        ]
    return actions


def batch_conflict_actions(candidates: list[PullRequest], detail: str = "") -> list[Action]:
    """Batch branches don't merge cleanly together: hold the **whole** batch at
    ``review-passed`` (no label edits) and flag the conflict on each PR with a signed comment.
    No ``needs-human`` — a rebase clears it, which the freshness/nudge machinery re-checks."""
    batch = ", ".join(f"#{pr.number}" for pr in candidates)
    where = f" (conflict at `{detail}`)" if detail else ""
    actions: list[Action] = []
    for pr in candidates:
        actions.append(
            Action(
                ActionKind.COMMENT,
                pr.number,
                _sign(
                    f"Batch test-merge conflict: the promote-eligible batch ({batch}) does not "
                    f"merge cleanly onto the current master tip{where}. Holding the whole batch "
                    f"at `status:review-passed` — not promoting. Please rebase/resolve so the "
                    f"branches compose, and the batch gate will re-run."
                ),
                on_pr=True,
                reason="batch-conflict",
            )
        )
    return actions


def batch_gate_red_actions(candidates: list[PullRequest], failing_gate: str) -> list[Action]:
    """The merged tree is red (``ruff``/``mypy``/``pytest`` failed on the combined branches):
    hold the **whole** batch at ``review-passed`` (no promotion), name the failing gate on each
    PR with a signed comment, and add ``needs-human`` — a combined-only failure needs a human to
    decide which PR to change."""
    batch = ", ".join(f"#{pr.number}" for pr in candidates)
    actions: list[Action] = []
    for pr in candidates:
        if pr.task is not None:
            actions.append(
                Action(ActionKind.ADD_LABEL, pr.task, NEEDS_HUMAN, reason="batch-gate-red")
            )
        actions.append(
            Action(
                ActionKind.COMMENT,
                pr.number,
                _sign(
                    f"Batch test-merge gate failed: the promote-eligible batch ({batch}) merges "
                    f"cleanly but `{failing_gate}` fails on the combined tree — a break that only "
                    f"appears when these PRs are merged together. Holding the whole batch at "
                    f"`status:review-passed` (not promoting) and flagging for a human to decide "
                    f"which PR to change."
                ),
                on_pr=True,
                reason="batch-gate-red",
            )
        )
    return actions


def _normalize(
    board: Board,
) -> tuple[list[Action], dict[int, frozenset[str]], set[int], set[int]]:
    """Shared self-heal + invariant analysis: returns ``(heal actions, healed primaries,
    violators, skip)``. The skip set (issues normalized this pass) is excluded from the
    downstream sweeps so a strip and a reap/promote can't issue conflicting label edits on one
    issue in a single pass. Used by both :func:`reconcile` and :func:`batch_candidates` so the
    batch and the inline-deferral decision share one source of truth."""
    heal, healed = _self_heal_stale(board.issues)
    violators = _invariant_violators(board.issues, healed)
    skip = violators | {a.number for a in heal}
    return heal, healed, violators, skip


def reconcile(board: Board, *, now: datetime, stale_after: timedelta) -> list[Action]:
    """Return every action needed to drive ``board`` to its correct pipeline state."""
    heal, healed, violators, skip = _normalize(board)
    # When 2+ PRs are promote-eligible in one pass, defer their promotion from the inline R3 path
    # to the shell's batch test-merge gate (#247); a lone candidate still promotes inline.
    candidates = select_promotion_candidates(board, skip)
    batch_deferred = {pr.number for pr in candidates} if len(candidates) >= 2 else set()
    return [
        *heal,
        *_flag_invariant(board.issues, violators, healed),
        *_unblock(board.issues, board.blocker_state, skip=skip),
        *_reap_stale(board.issues, now, stale_after, skip=skip),
        *_promote_and_refresh(board, skip=skip, batch_deferred=batch_deferred),
    ]
