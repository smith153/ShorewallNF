"""Unit tests for the reconcile shell's pure parsers (issue #106).

These four helpers turn raw `gh` output into the core's board snapshot; a parse bug here is a
wrong-direction mutation (premature un-block, destructive reap, wrong promote), so they are
guarded like the core rules.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

import pytest
from reconcile.core import ActionKind, Board, Issue, Mergeability, PullRequest
from reconcile.run import (
    BatchResult,
    _blocked_by,
    _ci_green,
    _freshness,
    _linked_task,
    _mergeability,
    _nudged_for_head,
    _process_batch,
    _rebase_marker,
    _run_gate,
    _test_merge_batch,
)

NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)

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


# --- _mergeability: only READY promotes; BEHIND/CONFLICTING nudge; UNKNOWN/DRAFT wait -------


def test_mergeability_ready_when_known_good() -> None:
    # up to date / promotable — BLOCKED just means "awaiting the human review" gate.
    for state in ("CLEAN", "BLOCKED", "UNSTABLE", "HAS_HOOKS"):
        assert _mergeability(state) is Mergeability.READY, state


def test_mergeability_distinguishes_behind_from_conflicting() -> None:
    # BEHIND (cleanly behind) and DIRTY (true conflict) map to distinct states so R3c can
    # escalate only a persistent conflict, while a plain BEHIND is only ever nudged.
    assert _mergeability("BEHIND") is Mergeability.BEHIND
    assert _mergeability("DIRTY") is Mergeability.CONFLICTING


def test_mergeability_pending_for_unknown_or_draft() -> None:
    # not-yet-computed or draft must NOT read as "behind" — no false rebase nudge, re-check next.
    assert _mergeability("UNKNOWN") is Mergeability.PENDING
    assert _mergeability("DRAFT") is Mergeability.PENDING


# --- _nudged_for_head: per-head rebase-marker detection (the R3c persistence signal) --------


def test_nudged_for_head_true_when_marker_for_current_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_gh_json(*args: str) -> object:
        body = f"please rebase {_rebase_marker('abc123')}"
        return {"headRefOid": "abc123", "comments": [{"body": body}]}

    monkeypatch.setattr("reconcile.run._gh_json", fake_gh_json)
    assert _nudged_for_head(20) == (True, "abc123")


def test_nudged_for_head_false_when_marker_for_other_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # a marker keyed on a *previous* head must not count as nudged for the current head.
    def fake_gh_json(*args: str) -> object:
        body = f"please rebase {_rebase_marker('OLD-oid')}"
        return {"headRefOid": "abc123", "comments": [{"body": body}]}

    monkeypatch.setattr("reconcile.run._gh_json", fake_gh_json)
    assert _nudged_for_head(20) == (False, "abc123")


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


# --- batch test-merge gate (#247): shell orchestration of the joint merge + gate -------------


def _pr(number: int, task: int) -> PullRequest:
    return PullRequest(
        number=number, task=task, base_ref="master", ci_green=True,
        mergeability=Mergeability.READY, head_oid="h", reviewed_oid="h",
    )


def _board(*tasks: int) -> Board:
    issues = tuple(
        Issue(number=t, labels=frozenset({"status:review-passed"}), updated_at=NOW) for t in tasks
    )
    pulls = tuple(_pr(100 + t, task=t) for t in tasks)
    return Board(issues=issues, pulls=pulls)


# _run_gate: runs ruff -> mypy -> pytest, stops at the first red, strips GH_TOKEN


def test_run_gate_returns_none_when_all_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **kw):  # type: ignore[no-untyped-def]
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _run_gate("/tmp/x") is None
    # order matters: ruff, then mypy, then pytest
    assert [c[2] for c in seen] == ["ruff", "mypy", "pytest"]


def test_run_gate_stops_at_first_failing_and_names_it(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kw):  # type: ignore[no-untyped-def]
        rc = 1 if "mypy" in cmd else 0
        return subprocess.CompletedProcess(cmd, rc, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _run_gate("/tmp/x") == "mypy"


def test_run_gate_strips_gh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "secret")
    envs: list[dict[str, str]] = []

    def fake_run(cmd, **kw):  # type: ignore[no-untyped-def]
        envs.append(kw.get("env") or {})
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _run_gate("/tmp/x")
    assert envs and all("GH_TOKEN" not in e for e in envs)


# _test_merge_batch: worktree + sequential merges + gate, always cleaned up


def _stub_merge(monkeypatch: pytest.MonkeyPatch, *, conflict_on: str | None) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_git(*args, **kw):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        rc = 0
        if args[0] == "merge" and conflict_on is not None and conflict_on in args[-1]:
            rc = 1
        return subprocess.CompletedProcess(list(args), rc, "", "")

    monkeypatch.setattr("reconcile.run._git", fake_git)
    monkeypatch.setattr("reconcile.run._pr_branch", lambda n: f"task/{n - 100}")
    return calls


def test_test_merge_clean_runs_gate_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stub_merge(monkeypatch, conflict_on=None)
    monkeypatch.setattr("reconcile.run._run_gate", lambda cwd: None)
    result, detail = _test_merge_batch(list(_board(7, 8).pulls), _board(7, 8))
    assert result is BatchResult.CLEAN
    # both branches merged, worktree removed at the end
    assert ["worktree", "remove"] == [c[:2] for c in calls if c[:2] == ["worktree", "remove"]][0]
    assert sum(1 for c in calls if c[0] == "merge" and c[1] == "--no-edit") == 2


def test_test_merge_conflict_short_circuits_and_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stub_merge(monkeypatch, conflict_on="task/8")
    monkeypatch.setattr("reconcile.run._run_gate", lambda cwd: pytest.fail("gate must not run"))
    result, detail = _test_merge_batch(list(_board(7, 8).pulls), _board(7, 8))
    assert result is BatchResult.CONFLICT and "task/8" in detail
    assert any(c[:2] == ["merge", "--abort"] for c in calls)
    assert any(c[:2] == ["worktree", "remove"] for c in calls)  # still cleaned up


def test_test_merge_gate_red(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_merge(monkeypatch, conflict_on=None)
    monkeypatch.setattr("reconcile.run._run_gate", lambda cwd: "pytest")
    result, detail = _test_merge_batch(list(_board(7, 8).pulls), _board(7, 8))
    assert result is BatchResult.GATE_RED and detail == "pytest"


# _process_batch: map the merge outcome to the right pure action set


def _promoted(acts: list) -> set[int]:  # type: ignore[type-arg]
    return {
        a.number
        for a in acts
        if a.kind is ActionKind.ADD_LABEL and a.value == "status:ready-to-merge"
    }


def test_process_batch_clean_promotes_all(monkeypatch: pytest.MonkeyPatch) -> None:
    board = _board(7, 8)
    monkeypatch.setattr("reconcile.run._test_merge_batch", lambda c, b: (BatchResult.CLEAN, ""))
    acts = _process_batch(list(board.pulls), board)
    assert _promoted(acts) == {7, 8}


def test_process_batch_conflict_flags_no_promote(monkeypatch: pytest.MonkeyPatch) -> None:
    board = _board(7, 8)
    monkeypatch.setattr(
        "reconcile.run._test_merge_batch", lambda c, b: (BatchResult.CONFLICT, "task/8")
    )
    acts = _process_batch(list(board.pulls), board)
    assert _promoted(acts) == set()
    assert all(a.kind is ActionKind.COMMENT for a in acts) and len(acts) == 2


def test_process_batch_gate_red_flags_needs_human(monkeypatch: pytest.MonkeyPatch) -> None:
    board = _board(7, 8)
    monkeypatch.setattr(
        "reconcile.run._test_merge_batch", lambda c, b: (BatchResult.GATE_RED, "pytest")
    )
    acts = _process_batch(list(board.pulls), board)
    assert _promoted(acts) == set()
    assert any(a.kind is ActionKind.ADD_LABEL and a.value == "needs-human" for a in acts)
