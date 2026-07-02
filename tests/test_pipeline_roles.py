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
