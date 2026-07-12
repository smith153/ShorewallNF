"""Docs-consistency guard for the Operations guide (task #331, extended by #394).

Keeps ``docs/operations.md`` wired to the real CLI: every lifecycle verb the CLI
actually exposes must appear in the guide (so the prose can't silently drift from
``cli._VERB_HELP``), the page must be in the published nav, and the systemd service
story is documented as shipped (epic #308), not left labeled forthcoming.
"""

from pathlib import Path

from shorewallnf import cli

ROOT = Path(__file__).resolve().parent.parent
OPERATIONS = ROOT / "docs" / "operations.md"


def test_operations_page_exists() -> None:
    assert OPERATIONS.is_file(), "docs/operations.md must exist"


def test_operations_documents_every_lifecycle_verb() -> None:
    """Every verb the CLI exposes is documented, so the guide can't drift from the CLI."""
    text = OPERATIONS.read_text()
    missing = [verb for verb in cli._VERB_HELP if f"`{verb}`" not in text]
    assert not missing, f"operations.md is missing lifecycle verbs: {missing}"


def test_operations_documents_the_try_verb() -> None:
    """The safe-apply `try` verb (#437) has an operator surface — it must be documented."""
    text = OPERATIONS.read_text()
    assert "`try`" in text, "operations.md must document the `try` safe-apply verb"
    assert "auto-revert" in text.lower(), "the `try` auto-revert semantics must be documented"


def test_operations_documents_the_interactive_safe_verbs() -> None:
    """The interactive `safe-reload`/`safe-start` verbs (#439) are an operator surface."""
    text = OPERATIONS.read_text()
    for verb in cli._SAFE_MESSAGE:
        assert f"`{verb}`" in text, f"operations.md must document the {verb} verb"
    assert "confirm" in text.lower(), "the confirm-or-revert semantics must be documented"


def test_operations_reconciles_the_persisting_verbs_statement() -> None:
    """`apply` is no longer the *only* persisting verb — a confirmed safe-reload/start persists too.

    Guards the reconciled doc line (#439 AC): the stale "apply is the only verb that persists"
    absolute must be gone so the prose can't contradict persist-on-confirm.
    """
    text = OPERATIONS.read_text()
    assert "only verb that persists" not in text


def test_operations_covers_persistence_path() -> None:
    """The persisted-state path (ADR-0030) is the operator's boot-restore anchor."""
    assert "/var/lib/shorewallnf/ruleset.json" in OPERATIONS.read_text()


def test_operations_documents_the_systemd_service() -> None:
    """systemd install has shipped (#392/#393) — documented as current, not forthcoming."""
    text = OPERATIONS.read_text()
    assert "forthcoming" not in text.lower(), (
        "systemd install has shipped; operations.md must not still label it forthcoming"
    )
    for unit in ("shorewallnf-restore.service", "shorewallnf.service"):
        assert unit in text, f"operations.md must document the {unit} unit"
    assert "systemctl enable --now" in text
    assert "systemctl stop shorewallnf" in text
    assert "ADR-0064" in text, "operations.md must cite the install-seam/ordering ADR (0064)"


def test_operations_documents_startup_enabled_analog() -> None:
    """The STARTUP_ENABLED replacement (systemd enablement) is documented, not a config knob."""
    text = OPERATIONS.read_text()
    assert "STARTUP_ENABLED" in text


def test_operations_in_published_nav() -> None:
    """Nav is filesystem-derived (awesome-pages, #353); operations.md is pinned in docs/.pages."""
    pages = (ROOT / "docs" / ".pages").read_text()
    assert "operations.md" in pages, "operations.md must be pinned in the docs/.pages nav order"
