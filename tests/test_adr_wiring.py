"""Guards that the living docs stay wired to the foundational decisions.

Task #13 referenced the Architecture-epic ADRs + module layout from ARCHITECTURE.md
and CLAUDE.md. These tests keep a future edit from silently dropping a reference, and
check CLAUDE.md's links resolve — test_docs_links.py is scoped to docs/ and does not
cover the repo-root CLAUDE.md.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ADR file slugs the living docs must point at, plus the module-layout doc.
REQUIRED_REFS = (
    "0001-ir-modeling",
    "0002-unified-inet-dual-stack",
    "0003-design-approach",
    "0004-error-handling",
    "module-layout.md",
)

_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _missing_refs(text: str) -> list[str]:
    return [ref for ref in REQUIRED_REFS if ref not in text]


def _broken_links(md: Path) -> list[str]:
    broken = []
    for match in _LINK.finditer(md.read_text()):
        target = match.group(1).split("#", 1)[0].strip()
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        if not (md.parent / target).resolve().exists():
            broken.append(target)
    return broken


def test_architecture_references_all_decisions() -> None:
    missing = _missing_refs((ROOT / "docs" / "ARCHITECTURE.md").read_text())
    assert not missing, f"ARCHITECTURE.md drops references: {missing}"


def test_claude_md_references_all_decisions() -> None:
    missing = _missing_refs((ROOT / "CLAUDE.md").read_text())
    assert not missing, f"CLAUDE.md drops references: {missing}"


def test_claude_md_links_resolve() -> None:
    broken = _broken_links(ROOT / "CLAUDE.md")
    assert not broken, f"CLAUDE.md has dangling links: {broken}"


def test_status_marks_architecture_epic_done() -> None:
    lines = (ROOT / "STATUS.md").read_text().splitlines()
    epic0 = next(ln for ln in lines if ln.strip().startswith("0.") and "Architecture" in ln)
    assert "Done" in epic0 or "✅" in epic0, f"epic #0 not marked done: {epic0!r}"
