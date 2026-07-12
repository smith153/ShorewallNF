"""Consistency guards for the pipeline role docs.

The pipeline is single-account: the maintainer and every agent post as the same
GitHub user, so a comment's author can't distinguish them. The convention that
fixes this (agents sign every comment; unsigned = human; each role heeds human
input) only works if it is actually written into every role. Guard it like code
so a role can't silently drop the step. See pipeline/workflow.md (Comment
attribution).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / "pipeline" / "workflow.md"
ROLES = sorted((ROOT / "pipeline" / "roles").glob("*.md"))

# The canonical signature trailer and the heed instruction the convention hinges on.
SIGN_TRAILER = "<!-- snf-agent:"
HEED_MARKER = "Heed human input"


def test_workflow_defines_comment_attribution() -> None:
    """workflow.md is the single source of truth for the signature + heed convention."""
    text = WORKFLOW.read_text()
    assert "## Comment attribution" in text, "workflow.md must define a Comment attribution section"
    assert SIGN_TRAILER in text, "workflow.md must specify the snf-agent signature trailer"
    assert HEED_MARKER in text, "workflow.md must state the heed-human rule"


def test_every_role_heeds_and_signs() -> None:
    """Every role must carry the heed-human step and the signing instruction."""
    assert ROLES, "no role docs found under pipeline/roles/"
    missing = []
    for role in ROLES:
        text = role.read_text()
        if HEED_MARKER not in text:
            missing.append(f"{role.name}: missing '{HEED_MARKER}' step")
        if SIGN_TRAILER not in text:
            missing.append(f"{role.name}: missing '{SIGN_TRAILER}' signing trailer")
    assert not missing, "role docs missing the comment convention:\n" + "\n".join(missing)


# --- atomic remote-ref task claim (replaces the label semaphore) --------------

IMPLEMENTER = ROOT / "pipeline" / "roles" / "implementer.md"
MERGE_READINESS = ROOT / "pipeline" / "roles" / "merge-readiness.md"
CLAIM_REF = "refs/heads/task/"


def test_workflow_documents_atomic_ref_claim() -> None:
    """Collision avoidance must describe the ref-as-mutex claim, not a label semaphore."""
    text = WORKFLOW.read_text()
    assert CLAIM_REF in text, "workflow.md must document the task claim ref"
    assert "git/refs" in text, "workflow.md must show atomic ref creation as the claim"
    assert "422" in text, "workflow.md must note 422 = already claimed"


def test_implementer_claims_via_atomic_ref() -> None:
    """The Implementer claims by creating the ref and handles the already-claimed case."""
    text = IMPLEMENTER.read_text()
    assert "git/refs" in text and CLAIM_REF in text, "implementer must create the claim ref"
    assert "422" in text, "implementer must handle 422 (already claimed)"


def test_merge_readiness_reclaim_deletes_ref() -> None:
    """Reclaiming a stale claim must delete the ref so the task can be re-claimed."""
    text = MERGE_READINESS.read_text()
    assert "DELETE" in text and CLAIM_REF in text, "reclaim must delete the claim ref"


def test_merge_readiness_documents_batch_test_merge_gate() -> None:
    """Two independently-green PRs can still break `master` when merged together — a rename vs.
    its caller, a CI count-guard vs. a new test, or several PRs appending to one file tail (#218).
    Per-PR CI can't catch this; the runbook must document a pre-merge test-merge of the ready batch
    onto the current `master` tip plus the full gate, with stacking guidance for additive conflicts
    and a not-safe-to-hand-off stop condition. Guard it against a silent drop."""
    text = MERGE_READINESS.read_text()
    lowered = text.lower()
    assert "test-merge" in lowered, "merge-readiness.md must document the batch test-merge step"
    assert "master tip" in lowered, "the batch must be test-merged onto the current master tip"
    for tool in ("ruff", "mypy", "pytest"):
        assert tool in lowered, f"the batch test-merge must run the full gate (missing {tool})"
    assert "stack" in lowered, "must give stacking guidance for additive same-file conflicts"


# --- atomic epic-claim for the Decomposer (retires status:decomposing) --------

DECOMPOSER = ROOT / "pipeline" / "roles" / "epic-decomposer.md"
EPIC_REF = "refs/heads/epic/"


def test_decomposer_claims_via_atomic_ref() -> None:
    """The Decomposer claims an epic via an epic ref and handles the already-claimed case."""
    text = DECOMPOSER.read_text()
    assert "git/refs" in text and EPIC_REF in text, "decomposer must claim via an epic ref"
    assert "422" in text, "decomposer must handle 422 (already being decomposed)"


def test_status_decomposing_label_retired() -> None:
    """The epic claim is now an atomic ref, not a label — neither the pipeline docs nor the
    canonical label config (`.github/labels.yml`) may reference it."""
    sources = [*(ROOT / "pipeline").rglob("*.md"), ROOT / ".github" / "labels.yml"]
    lingering = [
        src.relative_to(ROOT).as_posix()
        for src in sources
        if "status:decomposing" in src.read_text()
    ]
    assert not lingering, "retired status:decomposing still referenced in:\n" + "\n".join(lingering)


# --- reconcile freshness depends on the reviewer casting a GitHub review (#109) -----

CODE_REVIEWER = ROOT / "pipeline" / "roles" / "code-reviewer.md"


def test_code_reviewer_casts_verdict_via_gh_pr_review() -> None:
    """The reconcile Action's freshness check (scripts/reconcile/run.py::_freshness) only sees
    GitHub reviews (`reviews[].commit.oid`), so the reviewer MUST cast its verdict via
    `gh pr review`, never a plain `gh pr comment` — otherwise `reviewed_oid` stays `None` and R4
    strands the PR in `status:in-review`. Guard the command and its rationale against a silent
    drop by a future edit."""
    text = CODE_REVIEWER.read_text()
    assert "gh pr review" in text, "code-reviewer.md must cast the verdict via `gh pr review`"
    assert "gh pr comment" in text, (
        "code-reviewer.md must warn against a plain `gh pr comment` for the verdict"
    )
    assert "freshness" in text, (
        "code-reviewer.md must state the reconcile-freshness reason (only GitHub reviews are seen)"
    )


def test_code_reviewer_rechecks_status_before_casting_verdict() -> None:
    """Concurrent reviewers share one account and the verdict write (`gh pr review` + label swap)
    is not atomic, so a late reviewer can stack a second primary status onto an already-advanced
    task (#119). The reviewer MUST re-read the task status immediately before casting and no-op
    if it is no longer `status:in-review`. Guard the step against a silent drop."""
    text = CODE_REVIEWER.read_text()
    lowered = text.lower()
    assert "re-read" in lowered or "re-check" in lowered, (
        "code-reviewer.md must tell the reviewer to re-read the task status before casting"
    )
    assert "#119" in text, "code-reviewer.md must cite the double-cast race (#119) it prevents"


# --- roles never strip status:blocked; only reconcile R1 clears it (#146) ----------

BLOCKED_INVARIANT_ROLES = [
    ROOT / "pipeline" / "roles" / "code-reviewer.md",
    ROOT / "pipeline" / "roles" / "implementer.md",
    ROOT / "pipeline" / "roles" / "fixer.md",
]


def test_roles_preserve_status_blocked() -> None:
    """A role swaps only the primary `status:*` label and never removes `status:blocked` — that
    dependency gate is cleared solely by the reconcile un-block sweep (R1). Stripping it erased
    the dependency signal in the #125/#142 incident (#146). Guard the invariant in every role
    that swaps status against a silent drop by a future edit."""
    missing = []
    for role in BLOCKED_INVARIANT_ROLES:
        text = role.read_text()
        lowered = text.lower()
        if "status:blocked" not in text:
            missing.append(f"{role.name}: must reference status:blocked")
        if "never remove" not in lowered and "never strip" not in lowered:
            missing.append(f"{role.name}: must state it never removes/strips status:blocked")
    assert not missing, (
        "role docs missing the blocked-preservation invariant:\n" + "\n".join(missing)
    )


# --- stacking sanctioned for flow + bounded blocked-claim to stack (#148) ----------


def _missing_bounded_claim(text: str) -> list[str]:
    """Return which elements of the bounded blocked-claim-to-stack rule (#148) are absent.

    An implementer may claim a `status:blocked` task *to stack it* only when every open blocker
    is already approved (`review-passed`/`ready-to-merge`), basing the PR on the blocker's
    `task/<N>` branch and keeping `status:blocked`."""
    lowered = text.lower()
    missing = []
    if "status:blocked" not in text:
        missing.append("claim a status:blocked task")
    if "review-passed" not in text:
        missing.append("blocker review-passed")
    if "ready-to-merge" not in text:
        missing.append("blocker ready-to-merge")
    if "task/<n>" not in lowered:
        missing.append("base PR on blocker's task/<N> branch")
    if "keeps `status:blocked`" not in lowered and "keep `status:blocked`" not in lowered:
        missing.append("keep status:blocked")
    return missing


def test_workflow_sanctions_stacking_for_flow() -> None:
    """workflow.md must sanction stacking BOTH to avoid conflicting changes AND to keep delivery
    flowing when the human merge gate is closed (#148), not conflicts only."""
    lowered = WORKFLOW.read_text().lower()
    assert "conflict" in lowered, "workflow.md must keep the conflict-avoidance stacking reason"
    assert "keep delivery flowing" in lowered, (
        "workflow.md must sanction stacking to keep delivery flowing"
    )
    assert "merge gate is closed" in lowered, (
        "workflow.md must tie flow-stacking to the closed human merge gate"
    )


def test_workflow_stacking_notation_is_base_branch_no_label() -> None:
    """The 'stacked' notation stays the PR base branch — no new label (#148)."""
    text = WORKFLOW.read_text()
    lowered = text.lower()
    assert "base_ref" in text or "base branch" in lowered, (
        "workflow.md must state the stacked notation is the PR base branch"
    )
    assert "no new label" in lowered, "workflow.md must state no new label is introduced"


def test_workflow_bounded_blocked_claim_to_stack() -> None:
    """workflow.md must state the bounded claim exception exactly, at the claim rule (#148)."""
    missing = _missing_bounded_claim(WORKFLOW.read_text())
    assert not missing, "workflow.md missing bounded blocked-claim elements: " + ", ".join(missing)


def test_implementer_bounded_blocked_claim_to_stack() -> None:
    """implementer.md must state the same bounded claim exception (#148)."""
    missing = _missing_bounded_claim(IMPLEMENTER.read_text())
    assert not missing, (
        "implementer.md missing bounded blocked-claim elements: " + ", ".join(missing)
    )


# --- feature tasks must keep docs/reference/ current (#428) -------------------

GROOMER = ROOT / "pipeline" / "roles" / "task-groomer.md"
TASK_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "task.yml"
DOCS_REF = "docs/reference/"


def test_decomposer_writes_docs_currency_ac() -> None:
    """Feature tasks shipped code while docs/reference/ went stale (#428). The Decomposer must
    write a docs-currency acceptance criterion for any user-facing task — update the relevant
    docs/reference/ page or state why none applies — with an explicit exemption for
    internal/test-only/tooling work. Guard it against a silent drop by a future edit."""
    text = DECOMPOSER.read_text()
    lowered = text.lower()
    assert DOCS_REF in text, (
        "epic-decomposer.md must require a docs/reference/ acceptance criterion"
    )
    assert "user-facing" in lowered or "user-observable" in lowered, (
        "epic-decomposer.md must scope the requirement to user-facing work"
    )
    assert "exempt" in lowered or "no user-facing change" in lowered, (
        "epic-decomposer.md must exempt internal/test-only/tooling tasks (which must say so)"
    )


def test_groomer_gates_docs_currency() -> None:
    """The Groomer's testable-AC check (#4) must gate docs currency: a feature task whose AC omits
    the docs/reference/ update is sent back (needs-refinement) unless it states no user-facing doc
    applies and why (#428). Guard the sub-check against a silent drop."""
    text = GROOMER.read_text()
    lowered = text.lower()
    assert DOCS_REF in text, "task-groomer.md must add a docs/reference/ currency sub-check"
    assert "needs-refinement" in lowered, (
        "task-groomer.md must send a docs-stale feature task back to needs-refinement"
    )
    assert "exempt" in lowered or "no user-facing" in lowered, (
        "task-groomer.md must honor the internal/test-only/tooling exemption"
    )


def test_task_template_prompts_docs_currency() -> None:
    """The task template's Acceptance criteria field must prompt the author for the
    docs/reference/ update (or a note that none applies) (#428)."""
    text = TASK_TEMPLATE.read_text()
    assert DOCS_REF in text, (
        "task.yml Acceptance criteria description must prompt for the docs/reference/ update"
    )
