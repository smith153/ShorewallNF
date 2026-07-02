"""Unit tests for the reconcile shell's pure parsers (issue #106).

These four helpers turn raw `gh` output into the core's board snapshot; a parse bug here is a
wrong-direction mutation (premature un-block, destructive reap, wrong promote), so they are
guarded like the core rules.
"""

from __future__ import annotations

import pytest
from reconcile.core import Mergeability
from reconcile.run import (
    _blocked_by,
    _ci_green,
    _freshness,
    _linked_task,
    _mergeability,
)

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


# --- _mergeability: only READY promotes; only BEHIND/DIRTY nudges; UNKNOWN/DRAFT wait -------


def test_mergeability_ready_when_known_good() -> None:
    # up to date / promotable — BLOCKED just means "awaiting the human review" gate.
    for state in ("CLEAN", "BLOCKED", "UNSTABLE", "HAS_HOOKS"):
        assert _mergeability(state) is Mergeability.READY, state


def test_mergeability_needs_rebase_only_for_behind_or_dirty() -> None:
    assert _mergeability("BEHIND") is Mergeability.NEEDS_REBASE
    assert _mergeability("DIRTY") is Mergeability.NEEDS_REBASE


def test_mergeability_pending_for_unknown_or_draft() -> None:
    # not-yet-computed or draft must NOT read as "behind" — no false rebase nudge, re-check next.
    assert _mergeability("UNKNOWN") is Mergeability.PENDING
    assert _mergeability("DRAFT") is Mergeability.PENDING


# --- _freshness: `gh pr view --json reviews,headRefOid` -> (head oid, reviewed oid) ---------


def test_freshness_reads_head_and_reviewed_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_gh_json(*args: str) -> object:
        calls.append(args)
        # `gh pr view --json reviews` returns a plain list; the latest is reviews[-1].
        return {"headRefOid": "abc123", "reviews": [{"commit": {"oid": "def456"}}]}

    monkeypatch.setattr("reconcile.run._gh_json", fake_gh_json)
    assert _freshness(20) == ("abc123", "def456")
    # a single `gh pr view <PR> --json reviews,headRefOid` — no GraphQL, no owner/name plumbing.
    assert calls == [("pr", "view", "20", "--json", "reviews,headRefOid")]


def test_freshness_none_when_no_review(monkeypatch: pytest.MonkeyPatch) -> None:
    # empty reviews list -> no reviewed oid -> not-current (R4 resets).
    def fake_gh_json(*args: str) -> object:
        return {"headRefOid": "abc123", "reviews": []}

    monkeypatch.setattr("reconcile.run._gh_json", fake_gh_json)
    assert _freshness(20) == ("abc123", None)
