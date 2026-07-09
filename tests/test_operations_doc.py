"""Docs-consistency guard for the Operations guide (task #331).

Keeps ``docs/operations.md`` wired to the real CLI: every lifecycle verb the CLI
actually exposes must appear in the guide (so the prose can't silently drift from
``cli._VERB_HELP``), the page must be in the published nav, and systemd install must
stay labeled forthcoming (epic #308) rather than documented as current.
"""

from pathlib import Path

from shorewallnf import cli

ROOT = Path(__file__).resolve().parent.parent
OPERATIONS = ROOT / "docs" / "operations.md"
MKDOCS = ROOT / "mkdocs.yml"


def test_operations_page_exists() -> None:
    assert OPERATIONS.is_file(), "docs/operations.md must exist"


def test_operations_documents_every_lifecycle_verb() -> None:
    """Every verb the CLI exposes is documented, so the guide can't drift from the CLI."""
    text = OPERATIONS.read_text()
    missing = [verb for verb in cli._VERB_HELP if f"`{verb}`" not in text]
    assert not missing, f"operations.md is missing lifecycle verbs: {missing}"


def test_operations_covers_persistence_path() -> None:
    """The persisted-state path (ADR-0030) is the operator's boot-restore anchor."""
    assert "/var/lib/shorewallnf/ruleset.json" in OPERATIONS.read_text()


def test_operations_labels_systemd_forthcoming() -> None:
    """systemd install is epic #308 (open) — documented as forthcoming, not current."""
    text = OPERATIONS.read_text()
    assert "#308" in text, "operations.md must reference the systemd epic (#308)"
    assert "forthcoming" in text.lower(), "systemd install must be labeled forthcoming"


def test_operations_in_published_nav() -> None:
    assert "operations.md" in MKDOCS.read_text(), "operations.md must be in the mkdocs nav"
