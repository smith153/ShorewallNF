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
* **R4 review-freshness** — reset a ``review-passed`` PR whose head moved past the review
  (the correct mechanism for the check merge-readiness.md still does via a nonexistent
  ``.reviews[-1].commit.oid`` field).
* **R5 one-status invariant** — flag any issue that does not carry exactly one primary
  ``status:*`` label; malformed issues are flagged, never otherwise mutated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

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

#: Machine-readable signature so the maintainer's "unsigned == human" rule (pipeline/
#: workflow.md#comment-attribution) still holds for comments this Action posts.
AGENT_SIGN = "<!-- snf-agent:reconcile -->"


class BlockerState(Enum):
    """Closed-state of a referenced blocker issue."""

    OPEN = "open"
    COMPLETED = "completed"  # closed as completed — the blocker was delivered
    NOT_PLANNED = "not_planned"  # closed as not planned — do NOT release dependents


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
    up_to_date: bool  # not BEHIND / DIRTY relative to base
    head_committed_at: datetime
    last_review_at: datetime | None


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
    """True iff the latest review was cast at or after the current head commit."""
    return pr.last_review_at is not None and pr.last_review_at >= pr.head_committed_at


def _invariant_violators(issues: tuple[Issue, ...]) -> set[int]:
    """Issues carrying some ``status:*`` label but not exactly one *primary* status."""
    return {i.number for i in issues if _has_status(i) and len(_primaries(i)) != 1}


def _flag_invariant(issues: tuple[Issue, ...], violators: set[int]) -> list[Action]:
    actions: list[Action] = []
    for issue in issues:
        if issue.number not in violators or NEEDS_HUMAN in issue.labels:
            continue  # healthy, or already escalated (one-shot — no comment spam)
        found = ", ".join(sorted(_primaries(issue))) or "none"
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


def _promote_and_refresh(board: Board, skip: set[int]) -> list[Action]:
    by_number = {i.number: i for i in board.issues}
    actions: list[Action] = []
    for pr in board.pulls:
        if pr.task is None or pr.task in skip:
            continue
        task = by_number.get(pr.task)
        if task is None or "status:review-passed" not in task.labels:
            continue
        if not _review_current(pr):
            # R4: head moved past the review — reset for re-review.
            actions += [
                Action(
                    ActionKind.REMOVE_LABEL, task.number, "status:review-passed", reason="freshness"
                ),
                Action(ActionKind.ADD_LABEL, task.number, "status:in-review", reason="freshness"),
                Action(
                    ActionKind.COMMENT,
                    pr.number,
                    _sign(
                        "Review is stale: new commits landed after the reviewed head, so "
                        "resetting to `status:in-review` for re-review."
                    ),
                    on_pr=True,
                    reason="freshness",
                ),
            ]
            continue
        # R3: promote only when green, up to date, and on master.
        if not (pr.ci_green and pr.up_to_date and pr.base_ref == "master"):
            continue
        actions += [
            Action(ActionKind.REMOVE_LABEL, task.number, "status:review-passed", reason="ready"),
            Action(ActionKind.ADD_LABEL, task.number, "status:ready-to-merge", reason="ready"),
            Action(
                ActionKind.COMMENT,
                pr.number,
                _sign(
                    "Merge-ready: CI green, AI review passed and current, up to date with "
                    "master. Awaiting human merge."
                ),
                on_pr=True,
                reason="ready",
            ),
        ]
    return actions


def reconcile(board: Board, *, now: datetime, stale_after: timedelta) -> list[Action]:
    """Return every action needed to drive ``board`` to its correct pipeline state."""
    violators = _invariant_violators(board.issues)
    return [
        *_flag_invariant(board.issues, violators),
        *_unblock(board.issues, board.blocker_state, skip=violators),
        *_reap_stale(board.issues, now, stale_after, skip=violators),
        *_promote_and_refresh(board, skip=violators),
    ]
