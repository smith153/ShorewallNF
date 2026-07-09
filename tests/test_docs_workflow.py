"""Guards for the docs workflow's PR validation gate (issue #345).

`docs.yml` must validate docs on pull requests (`mkdocs build --strict`) without
deploying, keeping least-privilege permissions on the PR path, while the existing
master push build+deploy path stays intact. See SECURITY.md (least-privilege token,
no PR deploy).

Parsed as text (no PyYAML dep), matching the convention in test_docs_links.py.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_WORKFLOW = ROOT / ".github" / "workflows" / "docs.yml"

PATHS = ("docs/**", "mkdocs.yml", ".github/workflows/docs.yml")


def _text() -> str:
    return DOCS_WORKFLOW.read_text()


def _job(text: str, name: str) -> str:
    """Return the body of a top-level job block (2-space indented key)."""
    m = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text, re.M | re.S)
    assert m, f"job {name!r} not found in docs.yml"
    return m.group(1)


def test_pull_request_trigger_paths_filtered() -> None:
    """A paths-filtered pull_request trigger covers the same set as push."""
    text = _text()
    assert re.search(r"^  pull_request:$", text, re.M), (
        "docs.yml must trigger on pull_request"
    )
    # Each path appears once under push, once under pull_request.
    for path in PATHS:
        assert text.count(f'"{path}"') == 2, f"{path} must be filtered on both triggers"


def test_pr_job_is_least_privilege_strict_build_no_deploy() -> None:
    """The PR job runs `mkdocs build --strict`, contents:read only, and never deploys."""
    text = _text()
    assert "if: github.event_name == 'pull_request'" in text, (
        "a PR-only job must be gated to pull_request events"
    )
    pr_job = _job(text, "pr-build")
    assert "if: github.event_name == 'pull_request'" in pr_job
    assert "mkdocs build --strict" in pr_job
    assert "contents: read" in pr_job
    # No Pages write scope and no deploy/upload steps on the PR path.
    for forbidden in ("pages: write", "id-token", "deploy-pages", "upload-pages-artifact"):
        assert forbidden not in pr_job, f"PR job must not contain {forbidden!r}"


def test_master_build_and_deploy_intact_but_guarded() -> None:
    """The master build+deploy path is preserved and excluded from pull_request."""
    text = _text()
    build = _job(text, "build")
    assert "if: github.event_name != 'pull_request'" in build, (
        "the pages build job must be guarded against pull_request events"
    )
    assert "mkdocs build --strict --site-dir _site" in build
    assert "upload-pages-artifact" in build
    assert "deploy-pages" in _job(text, "deploy")
