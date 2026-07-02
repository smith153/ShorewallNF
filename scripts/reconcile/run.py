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
from datetime import UTC, datetime, timedelta
from typing import Any

from reconcile.core import (
    Action,
    ActionKind,
    BlockerState,
    Board,
    Issue,
    Mergeability,
    PullRequest,
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


def _nudged_for_head(number: int) -> tuple[bool, str]:
    """``(already-nudged-for-current-head, head-oid)``. Keyed on the head SHA, not a timestamp,
    so it's immune to committer-clock skew: a nudge repeats only when the head actually changes."""
    info = _gh_json("pr", "view", str(number), "--json", "headRefOid,comments")
    oid = str(info["headRefOid"])
    marker = _rebase_marker(oid)
    hit = any(marker in str(c.get("body") or "") for c in (info["comments"] or []))
    return hit, oid


def _try(*args: str) -> None:
    """Run a mutating gh command best-effort: one failure (e.g. deleting an already-gone ref, or
    a transient error) must not abort the rest of the run. Log and continue."""
    try:
        _gh(*args)
    except subprocess.CalledProcessError as e:
        print(f"  ! gh {' '.join(args)} failed: {(e.stderr or '').strip() or e}")


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
    for a in actions:
        target = f"PR #{a.number}" if a.on_pr else f"#{a.number}"
        head = a.value.splitlines()[0] if a.value else ""
        print(f"  {a.kind.value:12} {target:8} {a.reason:16} {head}")
    if apply:
        _apply(actions)
        print(f"reconcile: applied {len(actions)} actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
