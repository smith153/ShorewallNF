"""Imperative shell for the reconcile Action (issue #106).

Gathers a board snapshot from GitHub via ``gh``, runs the pure core
(:func:`reconcile.core.reconcile`), and applies the resulting actions — or, when
``RECONCILE_APPLY`` is not ``"true"``, prints them (dry-run is the default, so the workflow
is safe to land and enable deliberately). Config via env:

* ``RECONCILE_APPLY`` — ``"true"`` to mutate; anything else = dry-run (default).
* ``RECONCILE_STALE_DAYS`` — stale-claim reap window in days (default ``2``).
* ``GITHUB_REPOSITORY`` — ``owner/repo`` for ref deletion (set by Actions).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from reconcile.core import (
    Action,
    ActionKind,
    BlockerState,
    Board,
    Issue,
    Mergeability,
    PullRequest,
    batch_candidates,
    batch_conflict_actions,
    batch_gate_red_actions,
    batch_promote_actions,
    reconcile,
)

# GitHub's PR→issue closing keywords (any, with optional colon) link a PR to its task.
_CLOSES = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s*:?\s+#(\d+)", re.IGNORECASE)
_BLOCKED_BY_LINE = re.compile(r"blocked-by", re.IGNORECASE)
_ISSUE_REF = re.compile(r"#(\d+)")
_OK_CHECK = frozenset({"SUCCESS", "NEUTRAL", "SKIPPED"})
# BEHIND (cleanly behind) and DIRTY (true conflict) are both a definite "not up to date" that a
# rebase addresses — but kept distinct so R3c can escalate only a *persistent* DIRTY. UNKNOWN
# (mergeability not computed yet — common right after a push) and DRAFT are indeterminate: never
# promote on them, but never nudge "you're behind" either. Everything else is up to date.
_PENDING_MERGE = frozenset({"UNKNOWN", "DRAFT"})


def _gh(*args: str) -> str:
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True
    )
    return str(result.stdout)


def _gh_json(*args: str) -> Any:
    return json.loads(_gh(*args))


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _blocked_by(body: str) -> tuple[int, ...]:
    """Issue numbers this task is blocked by — every `#N` on any line mentioning `blocked-by`,
    so an inline list (`blocked-by #2, #3`) isn't under-counted (which would un-block early).
    Over-counting a stray same-line `#N` only keeps it blocked longer — the safe direction."""
    nums: list[int] = []
    for line in body.splitlines():
        if _BLOCKED_BY_LINE.search(line):
            nums.extend(int(n) for n in _ISSUE_REF.findall(line))
    return tuple(dict.fromkeys(nums))


def _mergeability(merge_state: str) -> Mergeability:
    """Map GitHub's ``mergeStateStatus`` to the R3 promote gate. BEHIND → ``BEHIND`` and DIRTY →
    ``CONFLICTING`` both earn a rebase nudge, kept distinct so R3c can escalate only a persistent
    conflict. UNKNOWN (not computed yet) and DRAFT are indeterminate → ``PENDING`` (skip, re-check
    next run) so they never trigger a false "behind" nudge. Everything else — CLEAN, BLOCKED
    (awaiting the human review), UNSTABLE, HAS_HOOKS… — is up to date and promotable."""
    state = merge_state.upper()
    if state == "BEHIND":
        return Mergeability.BEHIND
    if state == "DIRTY":
        return Mergeability.CONFLICTING
    if state in _PENDING_MERGE:
        return Mergeability.PENDING
    return Mergeability.READY


def _label_names(obj: Any) -> frozenset[str]:
    return frozenset(str(label["name"]) for label in obj)


def _fetch_issues() -> list[Issue]:
    raw = _gh_json(
        "issue", "list", "--state", "open", "--limit", "500",
        "--json", "number,labels,assignees,updatedAt,body",
    )
    issues: list[Issue] = []
    for item in raw:
        labels = _label_names(item["labels"])
        body = str(item["body"] or "")
        issues.append(
            Issue(
                number=int(item["number"]),
                labels=labels,
                updated_at=_dt(str(item["updatedAt"])),
                assignees=tuple(str(a["login"]) for a in item["assignees"]),
                blocked_by=_blocked_by(body),
                is_epic="type:epic" in labels,
            )
        )
    return issues


def _ci_green(rollup: Any) -> bool:
    checks = rollup or []
    if not checks:
        return False  # no signal that CI is green
    saw_success = False
    for check in checks:
        outcome = str(check.get("conclusion") or check.get("state") or "").upper()
        if outcome not in _OK_CHECK:
            return False
        saw_success = saw_success or outcome == "SUCCESS"
    return saw_success  # all-SKIPPED/NEUTRAL with no real success is not "green"


def _linked_task(body: str) -> int | None:
    match = _CLOSES.search(body)
    return int(match.group(1)) if match else None


def _freshness(number: int) -> tuple[str, str | None]:
    """Head oid and the oid the latest review was cast against — the inputs to the freshness
    check. Fetched per-PR (and only for review-passed PRs) with a single
    ``gh pr view <PR> --json reviews,headRefOid``: the CLI's ``reviews`` list exposes each
    review's ``commit.oid``, so no GraphQL (or owner/name plumbing) is needed.

    The reviewed oid is ``reviews[-1].commit.oid`` — populated **only** because the Code Reviewer
    casts its verdict via ``gh pr review`` (a COMMENTED review carries a ``commit``). If a
    reviewer used a plain ``gh pr comment`` instead, ``reviews`` would be empty, ``reviewed_oid``
    would be ``None``, and R4 would reset every ``review-passed`` task back to ``status:in-review``
    — nothing would reach ``ready-to-merge``. This coupling is load-bearing; see
    pipeline/roles/code-reviewer.md.
    """
    info = _gh_json("pr", "view", str(number), "--json", "reviews,headRefOid")
    head_oid = str(info["headRefOid"])
    reviews = info["reviews"] or []
    reviewed_oid = str(reviews[-1]["commit"]["oid"]) if reviews else None
    return head_oid, reviewed_oid


def _fetch_pulls(review_passed: set[int]) -> list[PullRequest]:
    raw = _gh_json(
        "pr", "list", "--state", "open", "--limit", "100",
        "--json", "number,baseRefName,mergeStateStatus,statusCheckRollup,body",
    )
    pulls: list[PullRequest] = []
    for item in raw:
        task = _linked_task(str(item["body"] or ""))
        if task in review_passed:  # freshness/R3c signals only affect review-passed tasks
            head_oid, reviewed_oid = _freshness(int(item["number"]))
            # R3c persistence: is there already a rebase nudge for the current head? (reuses the
            # per-head marker R3b writes — a timer-free "we asked once, nothing changed" signal.)
            rebase_nudged, _ = _nudged_for_head(int(item["number"]))
        else:
            head_oid, reviewed_oid = "", None
            rebase_nudged = False
        pulls.append(
            PullRequest(
                number=int(item["number"]),
                task=task,
                base_ref=str(item["baseRefName"]),
                ci_green=_ci_green(item["statusCheckRollup"]),
                mergeability=_mergeability(str(item["mergeStateStatus"] or "UNKNOWN")),
                head_oid=head_oid,
                reviewed_oid=reviewed_oid,
                rebase_nudged=rebase_nudged,
            )
        )
    return pulls


def _blocker_states(issues: list[Issue], open_numbers: set[int]) -> dict[int, BlockerState]:
    referenced = {b for issue in issues for b in issue.blocked_by}
    states: dict[int, BlockerState] = {}
    for number in referenced:
        if number in open_numbers:
            states[number] = BlockerState.OPEN
            continue
        try:
            info = _gh_json("issue", "view", str(number), "--json", "state,stateReason")
        except subprocess.CalledProcessError:
            states[number] = BlockerState.OPEN  # can't confirm — keep dependents blocked
            continue
        if str(info["state"]).upper() != "CLOSED":
            states[number] = BlockerState.OPEN
        elif str(info.get("stateReason") or "").upper() == "NOT_PLANNED":
            states[number] = BlockerState.NOT_PLANNED
        else:
            states[number] = BlockerState.COMPLETED
    return states


def _gather() -> Board:
    issues = _fetch_issues()
    review_passed = {i.number for i in issues if "status:review-passed" in i.labels}
    pulls = _fetch_pulls(review_passed)
    tasks_with_pr = {pr.task for pr in pulls if pr.task is not None}
    issues = [
        Issue(
            number=i.number,
            labels=i.labels,
            updated_at=i.updated_at,
            assignees=i.assignees,
            blocked_by=i.blocked_by,
            has_open_pr=i.number in tasks_with_pr,
            is_epic=i.is_epic,
        )
        for i in issues
    ]
    open_numbers = {i.number for i in issues}
    return Board(
        issues=tuple(issues),
        pulls=tuple(pulls),
        blocker_state=_blocker_states(issues, open_numbers),
    )


def _repo() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if repo:
        return repo
    return _gh("repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner").strip()


def _rebase_marker(oid: str) -> str:
    return f"<!-- snf-agent:reconcile:rebase:{oid} -->"


def _batch_marker(oid: str) -> str:
    return f"<!-- snf-agent:reconcile:batch:{oid} -->"


def _commented_for_head(number: int, marker_of: Any) -> tuple[bool, str]:
    """``(a comment carrying marker_of(head-oid) already exists, head-oid)``. Keyed on the head
    SHA, not a timestamp, so it's immune to committer-clock skew: the comment repeats only when
    the head actually changes. Shared by the rebase nudge and the batch conflict/gate flags so a
    persistent condition is flagged once per head, not every cron pass."""
    info = _gh_json("pr", "view", str(number), "--json", "headRefOid,comments")
    oid = str(info["headRefOid"])
    marker = marker_of(oid)
    hit = any(marker in str(c.get("body") or "") for c in (info["comments"] or []))
    return hit, oid


def _nudged_for_head(number: int) -> tuple[bool, str]:
    """``(already-nudged-for-current-head, head-oid)`` — the R3c persistence signal."""
    return _commented_for_head(number, _rebase_marker)


def _try(*args: str) -> None:
    """Run a mutating gh command best-effort: one failure (e.g. deleting an already-gone ref, or
    a transient error) must not abort the rest of the run. Log and continue."""
    try:
        _gh(*args)
    except subprocess.CalledProcessError as e:
        print(f"  ! gh {' '.join(args)} failed: {(e.stderr or '').strip() or e}")


class BatchResult(Enum):
    """Outcome of test-merging a promote-eligible batch together onto the current master tip."""

    CLEAN = "clean"  # every branch merged and the gate is green -> promote the batch
    CONFLICT = "conflict"  # branches don't merge cleanly -> hold + flag (no needs-human)
    GATE_RED = "gate_red"  # merged tree fails ruff/mypy/pytest -> hold + flag + needs-human


def _git(*args: str, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a git command, capturing output; the caller inspects ``returncode`` (git errors are a
    normal signal here — a merge conflict is data, not an exception)."""
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def _pr_branch(number: int) -> str:
    return str(_gh_json("pr", "view", str(number), "--json", "headRefName")["headRefName"])


def _run_gate(cwd: str) -> str | None:
    """Run ``ruff``/``mypy``/``pytest`` on the merged tree at ``cwd`` (mirrors ``make check`` —
    ``-m 'not nft'`` skips the privileged nft tier). Return the first failing gate's name, or
    ``None`` if all pass. ``GH_TOKEN`` is stripped from the child env so the *unreviewed* merged
    code executed here can never read the write token."""
    env = {k: v for k, v in os.environ.items() if k != "GH_TOKEN"}
    gates: tuple[tuple[str, list[str]], ...] = (
        ("ruff", ["python", "-m", "ruff", "check", "."]),
        ("mypy", ["python", "-m", "mypy"]),
        ("pytest", ["python", "-m", "pytest", "-q", "-m", "not nft"]),
    )
    for name, cmd in gates:
        result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  batch gate `{name}` failed (rc={result.returncode})")
            return name
    return None


def _test_merge_batch(
    candidates: list[PullRequest], board: Board
) -> tuple[BatchResult, str]:
    """Test-merge the candidate branches together onto the current ``origin/master`` tip in a
    throwaway worktree — each merge committed before the next — then run the gate. Returns
    ``(result, detail)`` where detail is the conflicting branch (CONFLICT) or the failing gate
    (GATE_RED). The worktree is always removed, and git/merge errors surface as a result, never
    an exception the caller must handle (it wraps this in its own isolation guard regardless)."""
    _git("fetch", "--no-tags", "--quiet", "origin")
    path = tempfile.mkdtemp(prefix="snf-batch-")
    os.rmdir(path)  # `git worktree add` wants to create the dir itself
    _git("worktree", "add", "--detach", path, "origin/master")
    try:
        for pr in candidates:
            branch = _pr_branch(pr.number)
            merged = _git("merge", "--no-edit", f"origin/{branch}", cwd=path)
            if merged.returncode != 0:
                _git("merge", "--abort", cwd=path)
                return BatchResult.CONFLICT, branch
        failing = _run_gate(path)
        if failing:
            return BatchResult.GATE_RED, failing
        return BatchResult.CLEAN, ""
    finally:
        _git("worktree", "remove", "--force", path)


def _process_batch(candidates: list[PullRequest], board: Board) -> list[Action]:
    """Run the batch test-merge gate and translate the outcome into the pure action set:
    promote every survivor (CLEAN), or hold the whole batch and flag it (CONFLICT / GATE_RED)."""
    result, detail = _test_merge_batch(candidates, board)
    print(f"  batch [{result.value}] {detail}".rstrip())
    if result is BatchResult.CLEAN:
        return batch_promote_actions(candidates, board)
    if result is BatchResult.CONFLICT:
        return batch_conflict_actions(candidates, detail)
    return batch_gate_red_actions(candidates, detail)


def _apply(actions: list[Action]) -> None:
    """Group label/assignee edits per issue into one ``gh issue edit`` call; then comments/refs.
    Every write is best-effort so one failing issue can't strand the rest of the board."""
    edits: dict[int, list[str]] = {}
    for a in actions:
        if a.kind is ActionKind.ADD_LABEL:
            edits.setdefault(a.number, []).extend(["--add-label", a.value])
        elif a.kind is ActionKind.REMOVE_LABEL:
            edits.setdefault(a.number, []).extend(["--remove-label", a.value])
        elif a.kind is ActionKind.UNASSIGN:
            edits.setdefault(a.number, []).extend(["--remove-assignee", a.value])
    for number, args in edits.items():
        _try("issue", "edit", str(number), *args)
    for a in actions:
        if a.kind is ActionKind.COMMENT:
            body = a.value
            if a.reason == "rebase":
                nudged, oid = _nudged_for_head(a.number)
                if nudged:
                    continue  # already nudged for this exact head — no spam
                body = f"{body}\n{_rebase_marker(oid)}"
            elif a.reason in ("batch-conflict", "batch-gate-red"):
                # Dedupe the batch flag per PR head: a persistent conflict / red gate is flagged
                # once and only repeats when the branch changes (mirrors the rebase nudge).
                flagged, oid = _commented_for_head(a.number, _batch_marker)
                if flagged:
                    continue
                body = f"{body}\n{_batch_marker(oid)}"
            verb = "pr" if a.on_pr else "issue"
            _try(verb, "comment", str(a.number), "--body", body)
        elif a.kind is ActionKind.DELETE_REF:
            _try("api", "--method", "DELETE", f"repos/{_repo()}/git/refs/heads/{a.value}")


def main() -> int:
    apply = os.environ.get("RECONCILE_APPLY", "").lower() == "true"
    stale_days = int(os.environ.get("RECONCILE_STALE_DAYS", "2"))
    board = _gather()
    actions = reconcile(
        board, now=datetime.now(UTC), stale_after=timedelta(days=stale_days)
    )
    mode = "APPLY" if apply else "DRY-RUN"
    print(f"reconcile [{mode}]: {len(board.issues)} issues, {len(board.pulls)} PRs "
          f"-> {len(actions)} actions")
    _print_actions(actions)
    if apply:
        _apply(actions)
        print(f"reconcile: applied {len(actions)} actions")
    _batch_gate(board, apply)
    return 0


def _print_actions(actions: list[Action]) -> None:
    for a in actions:
        target = f"PR #{a.number}" if a.on_pr else f"#{a.number}"
        head = a.value.splitlines()[0] if a.value else ""
        print(f"  {a.kind.value:12} {target:8} {a.reason:16} {head}")


def _batch_gate(board: Board, apply: bool) -> None:
    """The #247 batch test-merge gate: when 2+ PRs are promote-eligible in one pass, test-merge
    them together and promote only if the combined tree passes; otherwise hold + flag. Fully
    isolated — any git/gate error here is logged and swallowed so it can never abort the R1/R2/
    single-PR-R3 actions already applied above. The writes it emits are ``RECONCILE_APPLY``-gated
    exactly like the rest (and RECONCILE_APPLY is already false on ``pull_request`` events, so a
    test-merge of unreviewed code never drives a mutation from that unsafe context)."""
    try:
        candidates = batch_candidates(board)
        if len(candidates) < 2:
            return  # a batch of 0 or 1 promoted inline via reconcile() — nothing to test-merge
        nums = ", ".join(f"#{pr.number}" for pr in candidates)
        print(f"batch test-merge gate: {len(candidates)} promote-eligible PRs ({nums})")
        actions = _process_batch(candidates, board)
        _print_actions(actions)
        if apply:
            _apply(actions)
            print(f"batch gate: applied {len(actions)} actions")
    except Exception as e:  # noqa: BLE001 — isolation is the whole point (criterion 7)
        print(f"batch gate: error, skipped without affecting the rest of the pass: {e}")


if __name__ == "__main__":
    raise SystemExit(main())
