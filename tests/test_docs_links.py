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


def test_guard_detects_broken_link_and_anchor(tmp_path: Path) -> None:
    """Negative check so the positive guards above can't pass vacuously (#101 review).

    Runs the same scan predicates against a fixture with a known-broken link and a known-bad
    anchor: if ``_LINK``/``_relative_links``/``_heading_slugs`` ever regress (e.g. match
    nothing), these assertions fail loudly instead of the live scans silently going green.
    """
    (tmp_path / "target.md").write_text("# Real Heading\n")
    doc = tmp_path / "doc.md"
    doc.write_text(
        "[ok](target.md#real-heading)\n"     # valid file + valid anchor
        "[bad file](nope.md)\n"              # broken relative link
        "[bad anchor](target.md#missing)\n"  # valid file, missing anchor
    )

    # link existence — mirrors test_all_relative_doc_links_resolve
    broken_links = [t for t in _relative_links(doc) if not (doc.parent / t).resolve().exists()]
    assert broken_links == ["nope.md"], "link-existence scan failed to flag exactly the bad link"

    # anchor resolution — mirrors test_all_markdown_anchors_resolve
    broken_anchors = []
    for match in _LINK.finditer(doc.read_text()):
        url = match.group(1)
        if "#" not in url:
            continue
        target, _, anchor = url.partition("#")
        dest = (doc.parent / target).resolve() if target else doc
        if dest.suffix == ".md" and dest.exists() and anchor not in _heading_slugs(dest):
            broken_anchors.append(url)
    assert broken_anchors == ["target.md#missing"], "anchor scan failed to flag the bad anchor"


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
