"""Unit tests for the reconcile shell's pure parsers (issue #106).

These four helpers turn raw `gh` output into the core's board snapshot; a parse bug here is a
wrong-direction mutation (premature un-block, destructive reap, wrong promote), so they are
guarded like the core rules.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from reconcile.core import ActionKind, Board, Issue, Mergeability, PullRequest
from reconcile.run import (
    BatchResult,
    _batch_gate,
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
        # the merge carries leading `-c user.*` identity flags (#372); match on the branch arg
        if "merge" in args and conflict_on is not None and conflict_on in args[-1]:
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
    assert sum(1 for c in calls if "merge" in c and "--no-edit" in c) == 2


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


# --- regression (#372): real `git`, no ambient identity ---------------------------------------
# The stubbed tests above can't catch #372: a non-first branch that needs a real (non-ff) merge
# commit fails with "unable to auto-detect email address" when the runner has no git identity, and
# the gate must not mislabel that as a content conflict. These drive the real `git` binary with
# every identity source removed (author/committer env unset, system+global config -> /dev/null,
# no local `user.*`), reproducing a GitHub-hosted runner.


def _git_id_env() -> dict[str, str]:
    """A copy of the ambient env with an identity, for building fixtures (which need commits)."""
    return {
        **os.environ,
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }


def _git_setup(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=cwd, env=_git_id_env(), check=True, capture_output=True, text=True
    )


def _commit_file(repo: Path, name: str, content: str, message: str) -> None:
    (repo / name).write_text(content)
    _git_setup(repo, "add", name)
    _git_setup(repo, "commit", "-q", "-m", message)


def _strip_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every source git could read an identity from, so a merge commit can only be authored
    if the code under test supplies one itself."""
    for var in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)


def _clone_into_cwd(tmp_path: Path, origin: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Clone ``origin`` (so ``origin/*`` remote-tracking refs exist) and chdir into it — the cwd
    `_test_merge_batch` fetches and adds its throwaway worktree from. The fresh clone has no local
    `user.*`."""
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", str(origin), str(clone)],
        env=_git_id_env(), check=True, capture_output=True, text=True,
    )
    monkeypatch.chdir(clone)
    monkeypatch.setattr("reconcile.run._pr_branch", lambda n: f"task/{n - 100}")
    monkeypatch.setattr("reconcile.run._run_gate", lambda cwd: None)


def test_test_merge_no_identity_non_ff_second_branch_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#372: batch where the first branch fast-forwards but the second needs a real merge commit,
    on disjoint files, must return CLEAN with no ambient git identity — not a false CONFLICT."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git_setup(origin, "init", "-q", "-b", "master")
    _commit_file(origin, "base.txt", "base\n", "base")
    _git_setup(origin, "checkout", "-q", "-b", "task/365")  # ff-able: from master, adds a new file
    _commit_file(origin, "f365.txt", "f365\n", "add f365")
    _git_setup(origin, "checkout", "-q", "master")
    _git_setup(origin, "checkout", "-q", "-b", "task/367")  # diverges: needs a merge commit next
    _commit_file(origin, "f367.txt", "f367\n", "add f367")
    _git_setup(origin, "checkout", "-q", "master")

    _clone_into_cwd(tmp_path, origin, monkeypatch)
    _strip_identity(monkeypatch)

    result, detail = _test_merge_batch(list(_board(365, 367).pulls), _board(365, 367))
    assert result is BatchResult.CLEAN, f"expected CLEAN, got {result.value} at {detail!r}"


def test_test_merge_real_conflict_still_reported_without_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A genuine content conflict is still CONFLICT at the offending branch — the identity fix must
    not swallow real conflicts."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git_setup(origin, "init", "-q", "-b", "master")
    _commit_file(origin, "shared.txt", "base\n", "base")
    _git_setup(origin, "checkout", "-q", "-b", "task/365")  # ff-able edit of shared.txt
    _commit_file(origin, "shared.txt", "from-365\n", "365 edits shared")
    _git_setup(origin, "checkout", "-q", "master")
    _git_setup(origin, "checkout", "-q", "-b", "task/367")  # conflicting edit of the same line
    _commit_file(origin, "shared.txt", "from-367\n", "367 edits shared")
    _git_setup(origin, "checkout", "-q", "master")

    _clone_into_cwd(tmp_path, origin, monkeypatch)
    _strip_identity(monkeypatch)

    result, detail = _test_merge_batch(list(_board(365, 367).pulls), _board(365, 367))
    assert result is BatchResult.CONFLICT and "task/367" in detail


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


# --- _batch_gate: skip test-merging unreviewed code on pull_request events (#268) -------------


def test_batch_gate_skips_test_merge_on_pull_request(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 2+ promote-eligible PRs would normally trigger the joint test-merge + gate, but a
    # pull_request event runs the PR's unmerged code and can never promote (RECONCILE_APPLY is
    # false there), so the gate must not check out, merge, or execute any of it.
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setattr(
        "reconcile.run._test_merge_batch",
        lambda c, b: pytest.fail("test-merge must not run on pull_request"),
    )
    monkeypatch.setattr(
        "reconcile.run._run_gate", lambda cwd: pytest.fail("gate must not run on pull_request")
    )
    _batch_gate(_board(7, 8), apply=False)
    assert "skipped on pull_request" in capsys.readouterr().out


def _record_test_merge(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Stub ``_test_merge_batch`` to a no-op CLEAN and record each invocation."""
    called: list[bool] = []

    def fake_test_merge(c: object, b: object) -> tuple[BatchResult, str]:
        called.append(True)
        return BatchResult.CLEAN, ""

    monkeypatch.setattr("reconcile.run._test_merge_batch", fake_test_merge)
    return called


def test_batch_gate_runs_test_merge_on_non_pull_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every other trigger (schedule / issues / check_suite) is unchanged: 2+ eligible PRs still
    # get test-merged and gated exactly as #247 delivers.
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    called = _record_test_merge(monkeypatch)
    _batch_gate(_board(7, 8), apply=False)
    assert called == [True]


def test_batch_gate_workflow_dispatch_dry_run_still_previews_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The skip is scoped to pull_request, not to dry-run in general: a workflow_dispatch dry-run
    # (apply=False) must still run the gate so a human can preview the outcome.
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    called = _record_test_merge(monkeypatch)
    _batch_gate(_board(7, 8), apply=False)
    assert called == [True]
