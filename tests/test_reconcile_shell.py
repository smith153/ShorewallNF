"""Unit tests for the reconcile shell's pure parsers (issue #106).

These four helpers turn raw `gh` output into the core's board snapshot; a parse bug here is a
wrong-direction mutation (premature un-block, destructive reap, wrong promote), so they are
guarded like the core rules.
"""

from __future__ import annotations

from reconcile.run import _blocked_by, _ci_green, _linked_task, _up_to_date

# --- _linked_task: PR body -> governing task (all of GitHub's closing keywords) ------------


def test_linked_task_accepts_every_closing_keyword() -> None:
    for kw in ("Closes", "closes", "Close", "Closed", "Fixes", "fixed", "Resolves", "resolved"):
        assert _linked_task(f"{kw} #7") == 7, kw


def test_linked_task_accepts_optional_colon() -> None:
    assert _linked_task("Closes: #7") == 7
    assert _linked_task("Fixes:  #7") == 7


def test_linked_task_none_when_absent() -> None:
    assert _linked_task("just a description, no ref") is None
    assert _linked_task("mentions #7 but no keyword") is None


# --- _blocked_by: inline lists must not be under-counted (would un-block early) -------------


def test_blocked_by_captures_inline_list() -> None:
    assert _blocked_by("blocked-by #2, #3") == (2, 3)
    assert _blocked_by("blocked-by #2 and #3") == (2, 3)


def test_blocked_by_captures_multiline() -> None:
    assert _blocked_by("blocked-by #2\nblocked-by #3") == (2, 3)


def test_blocked_by_dedupes_and_empty() -> None:
    assert _blocked_by("blocked-by #2, #2") == (2,)
    assert _blocked_by("no dependencies here") == ()


# --- _ci_green: empty and all-SKIPPED must NOT count as green ------------------------------


def test_ci_green_requires_a_real_success() -> None:
    assert _ci_green([{"conclusion": "SUCCESS"}]) is True
    assert _ci_green([{"conclusion": "SUCCESS"}, {"conclusion": "SKIPPED"}]) is True
    assert _ci_green([{"state": "SUCCESS"}]) is True  # status contexts, not check runs


def test_ci_green_false_cases() -> None:
    assert _ci_green([]) is False  # no signal
    assert _ci_green(None) is False
    assert _ci_green([{"conclusion": "SKIPPED"}]) is False  # all-skipped is not green
    assert _ci_green([{"conclusion": "SUCCESS"}, {"conclusion": "FAILURE"}]) is False
    assert _ci_green([{"status": "PENDING"}]) is False


# --- _up_to_date: only promote on a definite not-behind state ------------------------------


def test_up_to_date_true_only_when_known_good() -> None:
    assert _up_to_date("CLEAN") is True
    assert _up_to_date("BLOCKED") is True  # awaiting the human review == ready to merge
    assert _up_to_date("HAS_HOOKS") is True


def test_up_to_date_false_for_behind_or_unknown() -> None:
    assert _up_to_date("BEHIND") is False
    assert _up_to_date("DIRTY") is False
    assert _up_to_date("UNKNOWN") is False  # not computed yet — never promote on a guess
    assert _up_to_date("DRAFT") is False
