"""Documentation-consistency guards.

Docs-only tasks (ADRs, ARCHITECTURE.md) are guarded the same way code is: a test
asserts the invariant the docs establish, so it can't silently drift. See
docs/adr/0002-unified-inet-dual-stack.md.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
# Directories whose markdown cross-links are guarded. pipeline/ role docs link each other and
# workflow.md (e.g. ../workflow.md#comment-attribution), so those must resolve too (#101).
LINKED_TREES = (DOCS, ROOT / "pipeline")

_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _relative_links(md: Path) -> list[str]:
    targets = []
    for match in _LINK.finditer(md.read_text()):
        target = match.group(1).split("#", 1)[0].strip()
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        targets.append(target)
    return targets


def test_all_relative_doc_links_resolve() -> None:
    """Every relative markdown link under docs/ and pipeline/ points at a real file."""
    broken = [
        f"{md.relative_to(ROOT)} -> {target}"
        for tree in LINKED_TREES
        for md in tree.rglob("*.md")
        for target in _relative_links(md)
        if not (md.parent / target).resolve().exists()
    ]
    assert not broken, "dangling doc/pipeline links:\n" + "\n".join(broken)


def _heading_slugs(md: Path) -> set[str]:
    # GitHub-style anchor: lowercase, drop punctuation (keep word chars/space/hyphen), spaces→-.
    slugs = set()
    for line in md.read_text().splitlines():
        if line.startswith("#"):
            text = re.sub(r"[^\w\s-]", "", line.lstrip("#").strip().lower())
            slugs.add(re.sub(r"\s+", "-", text))
    return slugs


def test_all_markdown_anchors_resolve() -> None:
    """Every relative link's ``#anchor`` matches a heading in the target markdown file."""
    broken = []
    for tree in LINKED_TREES:
        for md in tree.rglob("*.md"):
            for match in _LINK.finditer(md.read_text()):
                url = match.group(1)
                if url.startswith(("http://", "https://", "mailto:")) or "#" not in url:
                    continue
                target, _, anchor = url.partition("#")
                if not anchor:
                    continue
                dest = (md.parent / target).resolve() if target else md
                if dest.suffix == ".md" and dest.exists() and anchor not in _heading_slugs(dest):
                    broken.append(f"{md.relative_to(ROOT)} -> {url}")
    assert not broken, "dangling markdown anchors:\n" + "\n".join(broken)


def test_inet_family_scoping_is_resolved() -> None:
    """ADR-0002's deferred details (family scoping, cross-family zones) are settled.

    Guards against the decision being left advertised as 'still open' once task #9
    has resolved it, and against ARCHITECTURE.md not reflecting the resolution.
    """
    adr = (DOCS / "adr" / "0002-unified-inet-dual-stack.md").read_text()
    assert "## Resolution" in adr, "ADR-0002 must record the family-scoping resolution"
    assert "Details still open" not in adr, "ADR-0002 still advertises the details as open"

    arch = (DOCS / "ARCHITECTURE.md").read_text()
    assert "Family scoping" in arch, "ARCHITECTURE.md must document family scoping"
