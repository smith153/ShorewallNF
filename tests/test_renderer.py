"""Golden tests for the pure nft-JSON -> readable renderer (task #410, ADR-0065).

The renderer turns ``nft --json list ruleset`` output into the Option B annotated columnar
format (ADR-0065). It is pure — no root, no ``nft`` — so it is exercised entirely against
committed fixture JSON (RFC 5737/3849 doc ranges) with a stable expected-string per case.

Regenerate the expected ``.txt`` goldens with ``UPDATE_GOLDEN=1 pytest tests/test_renderer.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shorewallnf import renderer
from shorewallnf.errors import ConfigError

_FIX = Path(__file__).parent / "fixtures" / "show_rules"
_GOLD = Path(__file__).parent / "golden" / "show_rules"


def _load(name: str) -> dict[str, object]:
    return json.loads((_FIX / name).read_text())  # type: ignore[no-any-return]


def _assert_golden(text: str, name: str) -> None:
    path = _GOLD / f"{name}.txt"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.write_text(text)
        return
    assert path.exists(), f"missing golden {path} (run with UPDATE_GOLDEN=1)"
    assert text == path.read_text(), f"render drift vs {path.name}"


def test_render_filter_chains_columnar() -> None:
    # Multiple chains, rules with match+verdict, and an empty chain (forward) all in one table.
    text = renderer.render_rules(_load("running.json"), table="filter")
    _assert_golden(text, "filter")


def test_render_nat_table_scoped() -> None:
    # -t nat scopes to the nat table; a DNAT verdict renders its target in the detail column.
    text = renderer.render_rules(_load("running.json"), table="nat")
    _assert_golden(text, "nat")


def test_render_selected_chain_only() -> None:
    text = renderer.render_rules(_load("running.json"), table="filter", chains=("input",))
    assert "Chain input" in text
    assert "Chain forward" not in text and "Chain output" not in text


def test_render_ignores_co_resident_non_inet_tables() -> None:
    # A co-resident ip-family table in the fixture must never leak into inet output.
    text = renderer.render_rules(_load("running.json"), table="nat")
    assert "co_resident" not in text and "masquerade" not in text.lower()


def test_render_empty_ruleset_is_valid_not_a_crash() -> None:
    # Firewall stopped/cleared: no inet filter table present -> empty-but-valid section.
    text = renderer.render_rules(_load("stopped.json"), table="filter")
    _assert_golden(text, "empty")
    assert text  # non-empty string, no exception


def test_render_unknown_chain_fails_fast() -> None:
    # A typo against a running table is a fail-fast ConfigError (ADR-0004), not a crash.
    with pytest.raises(ConfigError, match="no chain 'nope'"):
        renderer.render_rules(_load("running.json"), table="filter", chains=("nope",))


def test_render_unknown_chain_on_stopped_firewall_degrades() -> None:
    # No table present at all -> can't validate names against a down firewall; degrade gracefully.
    text = renderer.render_rules(_load("stopped.json"), table="filter", chains=("input",))
    assert text  # empty-but-valid, no exception
