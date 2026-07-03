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
    head_oid = str(kw.pop("head_oid", "head-oid"))
    return PullRequest(
        number=number,
        task=task,
        base_ref=str(kw.pop("base_ref", "master")),
        ci_green=bool(kw.pop("ci_green", True)),
        mergeability=kw.pop("mergeability", Mergeability.READY),  # type: ignore[arg-type]
        head_oid=head_oid,
        # default: the review pins to the current head (current → promotable)
        reviewed_oid=kw.pop("reviewed_oid", head_oid),  # type: ignore[arg-type]
        rebase_nudged=bool(kw.pop("rebase_nudged", False)),
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
        [_pr(20, task=7, mergeability=Mergeability.BEHIND)],
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


def test_no_promote_when_task_still_blocked() -> None:
    # Defense-in-depth (#146): a still-blocked task must NOT be marked merge-ready even when its
    # PR is green, current, on master and mergeable. Only R1 (un-block) clears status:blocked.
    board = _board(
        [_issue(7, {"status:review-passed", "status:blocked"}, blocked_by=(8,))],
        [_pr(20, task=7)],
        blocker_state={8: BlockerState.OPEN},
    )
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") not in _kinds(_run(board), 7)


def test_promote_same_task_once_unblocked() -> None:
    # The identical task WITHOUT status:blocked IS promoted — proving the block is what holds it.
    board = _board([_issue(7, {"status:review-passed"})], [_pr(20, task=7)])
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") in _kinds(_run(board), 7)


# --- R4: review-freshness (reviewed commit oid vs. head oid, not timestamps) ---------------


def test_promote_when_review_pins_to_current_head() -> None:
    # reviewed oid == head oid -> review is current -> promote.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, head_oid="abc123", reviewed_oid="abc123")],
    )
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") in _kinds(_run(board), 7)


def test_reset_to_in_review_when_head_moved_past_review() -> None:
    # reviewed an older commit; head has since moved -> stale -> reset.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, head_oid="new-oid", reviewed_oid="old-oid")],
    )
    acts = _kinds(_run(board), 7)
    assert (ActionKind.REMOVE_LABEL, "status:review-passed") in acts
    assert (ActionKind.ADD_LABEL, "status:in-review") in acts
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") not in acts


def test_reset_when_no_review_recorded() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})], [_pr(20, task=7, reviewed_oid=None)]
    )
    assert (ActionKind.ADD_LABEL, "status:in-review") in _kinds(_run(board), 7)


def test_promote_and_refresh_are_mutually_exclusive() -> None:
    # current review -> promote, never both
    board = _board([_issue(7, {"status:review-passed"})], [_pr(20, task=7)])
    labels = _kinds(_run(board), 7)
    promoted = (ActionKind.ADD_LABEL, "status:ready-to-merge") in labels
    reset = (ActionKind.ADD_LABEL, "status:in-review") in labels
    assert promoted and not reset


# --- R3c: persistent conflict escalates review-passed -> changes-requested (Fixer owns it) --


def test_dirty_and_already_nudged_escalates_to_changes_requested() -> None:
    # DIRTY (true conflict) AND already rebase-nudged for this head -> hand to the Fixer.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, mergeability=Mergeability.CONFLICTING, rebase_nudged=True)],
    )
    acts = _run(board)
    k = _kinds(acts, 7)
    assert (ActionKind.REMOVE_LABEL, "status:review-passed") in k
    assert (ActionKind.ADD_LABEL, "status:changes-requested") in k
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") not in k
    escalations = [a for a in acts if a.reason == "conflict" and a.kind is ActionKind.COMMENT]
    assert len(escalations) == 1
    assert escalations[0].on_pr and escalations[0].number == 20
    assert AGENT_SIGN in escalations[0].value
    # escalation replaces the nudge — it does not also nudge on this pass
    assert not any(a.reason == "rebase" for a in acts)


def test_dirty_but_not_yet_nudged_only_nudges_no_escalation() -> None:
    # First dirty observation for this head: keep R3b behavior (nudge only), do NOT escalate.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, mergeability=Mergeability.CONFLICTING, rebase_nudged=False)],
    )
    acts = _run(board)
    assert (ActionKind.ADD_LABEL, "status:changes-requested") not in _kinds(acts, 7)
    nudges = [a for a in acts if a.reason == "rebase"]
    assert len(nudges) == 1 and nudges[0].on_pr and REBASE_TAG in nudges[0].value


def test_behind_not_dirty_never_escalates_even_when_nudged() -> None:
    # A merely-BEHIND (non-conflicting) PR is never escalated, even after being nudged.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, mergeability=Mergeability.BEHIND, rebase_nudged=True)],
    )
    acts = _run(board)
    assert (ActionKind.ADD_LABEL, "status:changes-requested") not in _kinds(acts, 7)
    assert [a for a in acts if a.reason == "rebase"]  # still just nudges


def test_conflict_escalation_is_idempotent_once_changes_requested() -> None:
    # After escalation the task is changes-requested; _promote_and_refresh no longer touches it.
    board = _board(
        [_issue(7, {"status:changes-requested"})],
        [_pr(20, task=7, mergeability=Mergeability.CONFLICTING, rebase_nudged=True)],
    )
    assert _run(board) == []


def test_freshness_reset_takes_precedence_over_conflict() -> None:
    # R4 (head moved past review) runs first — R3c only handles the head-unchanged case.
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [
            _pr(
                20,
                task=7,
                head_oid="new",
                reviewed_oid="old",
                mergeability=Mergeability.CONFLICTING,
                rebase_nudged=True,
            )
        ],
    )
    k = _kinds(_run(board), 7)
    assert (ActionKind.ADD_LABEL, "status:in-review") in k
    assert (ActionKind.ADD_LABEL, "status:changes-requested") not in k


def test_conflict_not_escalated_when_task_blocked() -> None:
    # A blocked task is held before mergeability; status:blocked is left intact (#146).
    board = _board(
        [_issue(7, {"status:review-passed", "status:blocked"}, blocked_by=(8,))],
        [_pr(20, task=7, mergeability=Mergeability.CONFLICTING, rebase_nudged=True)],
        blocker_state={8: BlockerState.OPEN},
    )
    k = _kinds(_run(board), 7)
    assert (ActionKind.ADD_LABEL, "status:changes-requested") not in k
    assert (ActionKind.REMOVE_LABEL, "status:blocked") not in k


def test_conflict_not_escalated_when_stacked() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [
            _pr(
                20,
                task=7,
                base_ref="task/6",
                mergeability=Mergeability.CONFLICTING,
                rebase_nudged=True,
            )
        ],
    )
    assert _run(board) == []


def test_conflict_not_escalated_when_ci_red() -> None:
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [
            _pr(
                20,
                task=7,
                ci_green=False,
                mergeability=Mergeability.CONFLICTING,
                rebase_nudged=True,
            )
        ],
    )
    assert _run(board) == []


def test_pending_not_escalated_even_when_nudged() -> None:
    # PENDING mergeability is indeterminate — never escalate (and never a false nudge).
    board = _board(
        [_issue(7, {"status:review-passed"})],
        [_pr(20, task=7, mergeability=Mergeability.PENDING, rebase_nudged=True)],
    )
    assert _run(board) == []


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


# --- R5: self-heal a stale claim status superseded by a later primary (#227) ---------------


def test_stale_implementation_ready_stripped_when_review_passed_present() -> None:
    # #195/#219: implementation-ready lingered into review-passed. Self-heal strips it instead
    # of flagging needs-human — the leftover claim label was a silent merge-gate stall.
    board = _board([_issue(9, {"status:implementation-ready", "status:review-passed"})])
    acts = _kinds(_run(board), 9)
    assert (ActionKind.REMOVE_LABEL, "status:implementation-ready") in acts
    assert (ActionKind.ADD_LABEL, "needs-human") not in acts
    assert (ActionKind.REMOVE_LABEL, "status:review-passed") not in acts


def test_stale_in_progress_stripped_when_in_review_present() -> None:
    # The PR-opened swap should drop in-progress; if it lingers under in-review, self-heal it.
    board = _board([_issue(9, {"status:in-progress", "status:in-review"})])
    acts = _kinds(_run(board), 9)
    assert (ActionKind.REMOVE_LABEL, "status:in-progress") in acts
    assert (ActionKind.ADD_LABEL, "needs-human") not in acts
    assert (ActionKind.REMOVE_LABEL, "status:in-review") not in acts


def test_self_heal_reports_a_signed_reason_comment() -> None:
    board = _board([_issue(9, {"status:implementation-ready", "status:review-passed"})])
    comments = [
        a for a in _run(board) if a.kind is ActionKind.COMMENT and a.reason == "stale-status"
    ]
    assert len(comments) == 1
    assert AGENT_SIGN in comments[0].value


def test_self_heal_is_a_noop_on_a_clean_single_status() -> None:
    board = _board([_issue(9, {"status:review-passed"})], [_pr(20, task=9)])
    assert not any(a.reason == "stale-status" for a in _run(board))


def test_self_healed_issue_promotes_on_next_pass() -> None:
    # Level-triggered: pass 1 only strips the stale label (issue skipped from the sweeps this
    # pass so a strip and a promote can't fight over the same labels); pass 2 — label gone —
    # promotes. The unlabeled event re-triggers reconcile, and cron backstops it.
    stale = _board(
        [_issue(9, {"status:implementation-ready", "status:review-passed"})], [_pr(20, task=9)]
    )
    acts1 = _kinds(_run(stale), 9)
    assert (ActionKind.REMOVE_LABEL, "status:implementation-ready") in acts1
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") not in acts1
    healed = _board([_issue(9, {"status:review-passed"})], [_pr(20, task=9)])
    assert (ActionKind.ADD_LABEL, "status:ready-to-merge") in _kinds(_run(healed), 9)


def test_ambiguous_two_late_primaries_still_flags_needs_human() -> None:
    # No strippable pre-review claim label -> self-heal can't decide -> flag for a human (R5).
    board = _board([_issue(9, {"status:review-passed", "status:changes-requested"})])
    acts = _kinds(_run(board), 9)
    assert (ActionKind.ADD_LABEL, "needs-human") in acts
    assert not any(a.reason == "stale-status" for a in _run(board))


def test_stale_stripped_and_remainder_flagged_when_still_ambiguous() -> None:
    # Strip the obvious stale claim label AND flag the genuinely ambiguous remainder.
    board = _board(
        [
            _issue(
                9,
                {
                    "status:implementation-ready",
                    "status:review-passed",
                    "status:changes-requested",
                },
            )
        ]
    )
    acts = _kinds(_run(board), 9)
    assert (ActionKind.REMOVE_LABEL, "status:implementation-ready") in acts
    assert (ActionKind.ADD_LABEL, "needs-human") in acts


def test_self_heal_never_strips_status_blocked() -> None:
    # #227 clarification: status:blocked is an orthogonal MODIFIER, not a primary — self-heal
    # strips the stale claim label and leaves status:blocked intact.
    board = _board(
        [
            _issue(
                9,
                {"status:implementation-ready", "status:review-passed", "status:blocked"},
                blocked_by=(2,),
            )
        ],
        blocker_state={2: BlockerState.OPEN},
    )
    acts = _kinds(_run(board), 9)
    assert (ActionKind.REMOVE_LABEL, "status:implementation-ready") in acts
    assert (ActionKind.REMOVE_LABEL, "status:blocked") not in acts
    assert (ActionKind.ADD_LABEL, "needs-human") not in acts


def test_self_heal_defers_to_a_human_flag() -> None:
    # A human-added needs-human is respected (consistent with unblock/reap) — don't auto-mutate.
    board = _board(
        [_issue(9, {"status:implementation-ready", "status:review-passed", "needs-human"})]
    )
    assert _run(board) == []


def test_earlier_primary_below_the_claim_labels_is_not_self_healed() -> None:
    # proposed + implementation-ready: the *earlier* label isn't a stale claim, and stripping
    # implementation-ready would keep the wrong one — so this stays a human-flagged violation.
    board = _board([_issue(9, {"status:proposed", "status:implementation-ready"})])
    acts = _kinds(_run(board), 9)
    assert (ActionKind.ADD_LABEL, "needs-human") in acts
    assert not any(a.reason == "stale-status" for a in _run(board))
