"""Docs-consistency guard for docs/concepts.md (task #352).

Per ADR-0005, only the `input` and `forward` base chains emit an explicit
established/related accept; `output`'s chain policy already defaults to accept, so it
carries no such rule. The Concepts page must not overstate this as applying to all
three base chains.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONCEPTS = ROOT / "docs" / "concepts.md"


def test_concepts_does_not_overstate_established_related_to_all_chains() -> None:
    text = CONCEPTS.read_text()
    assert "each chain first accepts already-established/related" not in text, (
        "concepts.md must not claim all three base chains accept established/related "
        "first — per ADR-0005, output carries no such rule"
    )


def test_concepts_scopes_established_related_accept_to_input_and_forward() -> None:
    text = CONCEPTS.read_text()
    assert "`input` and `forward`" in text and "established/related" in text, (
        "concepts.md must scope the established/related accept to input and forward"
    )
