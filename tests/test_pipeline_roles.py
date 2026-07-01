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
