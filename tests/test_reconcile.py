"""Unit tests for the reconcile Action's functional core (issue #106).

Each pipeline transition rule is a pure function over a board snapshot. Tests assert the
exact action set per rule and, crucially, that the rules are **idempotent** — a second pass
over the resulting state emits nothing (no duplicate label flips, no comment spam).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from reconcile.core import (
    AGENT_SIGN,
    REBASE_TAG,
    Action,
    ActionKind,
    BlockerState,
    Board,
    Issue,
    Mergeability,
    PullRequest,
    reconcile,
)

NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
STALE = timedelta(days=2)


def _issue(number: int, labels: set[str], **kw: object) -> Issue:
    return Issue(
        number=number,
        labels=frozenset(labels),
        updated_at=kw.pop("updated_at", NOW),  # type: ignore[arg-type]
        assignees=tuple(kw.pop("assignees", ())),  # type: ignore[arg-type]
        blocked_by=tuple(kw.pop("blocked_by", ())),  # type: ignore[arg-type]
        has_open_pr=bool(kw.pop("has_open_pr", False)),
        is_epic=bool(kw.pop("is_epic", False)),
    )


def _pr(number: int, task: int, **kw: object) -> PullRequest:
    return PullRequest(
        number=number,
        task=task,
        base_ref=str(kw.pop("base_ref", "master")),
        ci_green=bool(kw.pop("ci_green", True)),
        mergeability=kw.pop("mergeability", Mergeability.READY),  # type: ignore[arg-type]
        head_committed_at=kw.pop("head_committed_at", NOW - timedelta(hours=2)),  # type: ignore[arg-type]
        last_review_at=kw.pop("last_review_at", NOW - timedelta(hours=1)),  # type: ignore[arg-type]
    )


def _board(
    issues: list[Issue],
    pulls: list[PullRequest] | None = None,
    blocker_state: dict[int, BlockerState] | None = None,
) -> Board:
    return Board(
        issues=tuple(issues),
        pulls=tuple(pulls or ()),
        blocker_state=dict(blocker_state or {}),
    )


def _run(board: Board) -> list[Action]:
    return reconcile(board, now=NOW, stale_after=STALE)


def _kinds(actions: list[Action], number: int) -> set[tuple[ActionKind, str]]:
    return {(a.kind, a.value) for a in actions if a.number == number and not a.on_pr}


# --- global invariant: every comment is signed (workflow.md "unsigned == human") -----------


def test_every_comment_is_signed() -> None:
    board = _board(
        [
            _issue(1, {"status:blocked", "status:implementation-ready"}, blocked_by=(2,)),
            _issue(
                3,
                {"status:in-progress"},
                assignees=["bot"],
                updated_at=NOW - timedelta(days=5),
            ),
            _issue(9, {"status:in-review", "status:review-passed"}),  # invariant violation
        ],
        blocker_state={2: BlockerState.COMPLETED},
    )
    comments = [a for a in _run(board) if a.kind is ActionKind.COMMENT]
    assert comments, "expected at least one comment in this scenario"
    for c in comments:
        assert AGENT_SIGN in c.value, f"unsigned comment would read as human input: {c.value!r}"


# --- R1: un-block --------------------------------------------------------------------------


def test_unblock_when_all_blockers_completed() -> None:
    board = _board(
        [_issue(1, {"status:implementation-ready", "status:blocked"}, blocked_by=(2, 3))],
        blocker_state={2: BlockerState.COMPLETED, 3: BlockerState.COMPLETED},
    )
    assert (ActionKind.REMOVE_LABEL, "status:blocked") in _kinds(_run(board), 1)


def test_stays_blocked_when_a_blocker_still_open() -> None:
    board = _board(
        [_issue(1, {"status:implementation-ready", "status:blocked"}, blocked_by=(2, 3))],
        blocker_state={2: BlockerState.COMPLETED, 3: BlockerState.OPEN},
    )
    assert _run(board) == []


def test_not_planned_blocker_escalates_rather_than_releasing() -> None:
    board = _board(
        [_issue(1, {"status:implementation-ready", "status:blocked"}, blocked_by=(2,))],
        blocker_state={2: BlockerState.NOT_PLANNED},
    )
    acts = _kinds(_run(board), 1)
    assert (ActionKind.ADD_LABEL, "needs-human") in acts
    assert (ActionKind.REMOVE_LABEL, "status:blocked") not in acts


def test_unblock_is_idempotent_once_label_removed() -> None:
    # no status:blocked -> nothing to do (models the post-reconcile state)
    board = _board([_issue(1, {"status:implementation-ready"}, blocked_by=(2,))])
    assert _run(board) == []


# --- R2: stale-claim reap ------------------------------------------------------------------


def test_reap_stale_claim_swaps_and_unassigns_and_frees_ref() -> None:
    board = _board(
        [
            _issue(
                5,
                {"status:in-progress"},
                assignees=["alice"],
                updated_at=NOW - timedelta(days=3),
            )
        ]
    )
    acts = _run(board)
    kinds = _kinds(acts, 5)
    assert (ActionKind.REMOVE_LABEL, "status:in-progress") in kinds
    assert (ActionKind.ADD_LABEL, "status:implementation-ready") in kinds
    assert (ActionKind.UNASSIGN, "alice") in kinds
    assert any(a.kind is ActionKind.DELETE_REF and a.value == "task/5" for a in acts)


def test_no_reap_when_recently_touched() -> None:
    board = _board(
        [_issue(5, {"status:in-progress"}, assignees=["a"], updated_at=NOW - timedelta(hours=1))]
    )
    assert _run(board) == []


def test_no_reap_when_open_pr_exists() -> None:
    board = _board(
        [
            _issue(
                5,
                {"status:in-progress"},
                assignees=["a"],
                updated_at=NOW - timedelta(days=9),
                has_open_pr=True,
            )
        ]
    )
    assert _run(board) == []


# --- R3: ready-to-merge --------------------------------------------------------------------


def test_promote_ready_to_merge_when_all_green() -> None:
    board = _board([_issue(7, {"status:review-passed"})], [_pr(20, task=7)])
    acts = _run(board)
    assert (ActionKind.REMOVE_LABEL, "status:review-passed") in _kinds(acts, 7)
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") in _kinds(acts, 7)
    assert any(a.kind is ActionKind.COMMENT and a.on_pr and a.number == 20 for a in acts)


def test_no_promote_when_ci_red() -> None:
    board = _board([_issue(7, {"status:review-passed"})], [_pr(20, task=7, ci_green=False)])
    assert _run(board) == []


def test_behind_base_nudges_rebase_not_promote() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, mergeability=Mergeability.NEEDS_REBASE)],
    )
    acts = _run(board)
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") not in _kinds(acts, 7)
    nudges = [a for a in acts if a.reason == "rebase"]
    assert len(nudges) == 1
    assert nudges[0].on_pr and nudges[0].number == 20 and REBASE_TAG in nudges[0].value


def test_pending_mergeability_skips_silently() -> None:
    # mergeStateStatus UNKNOWN/DRAFT -> PENDING: never promote AND never a false "behind" nudge.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, mergeability=Mergeability.PENDING)],
    )
    assert _run(board) == []


def test_no_promote_when_stacked_on_non_master() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})], [_pr(20, task=7, base_ref="task/6-foo")]
    )
    assert _run(board) == []


# --- R4: review-freshness (fixes the .reviews[-1].commit.oid bug) --------------------------


def test_reset_to_in_review_when_head_moved_past_review() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, head_committed_at=NOW, last_review_at=NOW - timedelta(hours=3))],
    )
    acts = _kinds(_run(board), 7)
    assert (ActionKind.REMOVE_LABEL, "status:review-passed") in acts
    assert (ActionKind.ADD_LABEL, "status:in-review") in acts
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") not in acts


def test_reset_when_no_review_recorded() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})], [_pr(20, task=7, last_review_at=None)]
    )
    assert (ActionKind.ADD_LABEL, "status:in-review") in _kinds(_run(board), 7)


def test_promote_and_refresh_are_mutually_exclusive() -> None:
    # current review -> promote, never both
    board = _board([_issue(7, {"status:review-passed"})], [_pr(20, task=7)])
    labels = _kinds(_run(board), 7)
    promoted = (ActionKind.ADD_LABEL, "status:ready-to-merge") in labels
    reset = (ActionKind.ADD_LABEL, "status:in-review") in labels
    assert promoted and not reset


# --- R5: one-status invariant flag ---------------------------------------------------------


def test_flag_two_primary_status_labels() -> None:
    board = _board([_issue(9, {"status:in-review", "status:review-passed"})])
    assert (ActionKind.ADD_LABEL, "needs-human") in _kinds(_run(board), 9)


def test_flag_zero_primary_with_only_blocked() -> None:
    board = _board([_issue(9, {"status:blocked"})])
    assert (ActionKind.ADD_LABEL, "needs-human") in _kinds(_run(board), 9)


def test_healthy_blocked_plus_one_primary_not_flagged() -> None:
    board = _board(
        [_issue(9, {"status:implementation-ready", "status:blocked"}, blocked_by=(2,))],
        blocker_state={2: BlockerState.OPEN},
    )
    assert (ActionKind.ADD_LABEL, "needs-human") not in _kinds(_run(board), 9)


def test_issue_without_any_status_label_is_ignored() -> None:
    board = _board([_issue(9, {"type:docs"})])
    assert _run(board) == []


def test_invariant_flag_is_idempotent_when_needs_human_present() -> None:
    board = _board([_issue(9, {"status:in-review", "status:review-passed", "needs-human"})])
    assert _run(board) == []


def test_malformed_issue_is_flagged_not_otherwise_mutated() -> None:
    # two primaries AND blocked with completed blocker: flag only, do NOT auto-unblock a
    # malformed issue.
    board = _board(
        [
            _issue(
                9,
                {"status:in-review", "status:review-passed", "status:blocked"},
                blocked_by=(2,),
            )
        ],
        blocker_state={2: BlockerState.COMPLETED},
    )
    acts = _kinds(_run(board), 9)
    assert (ActionKind.ADD_LABEL, "needs-human") in acts
    assert (ActionKind.REMOVE_LABEL, "status:blocked") not in acts
