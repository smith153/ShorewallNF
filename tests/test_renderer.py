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


# ---- show zones / show policies: pure IR renderers (task #411, ADR-0065) ----------

from shorewallnf import ir  # noqa: E402

_GOLD_ZONES = Path(__file__).parent / "golden" / "show_zones"
_GOLD_POLICIES = Path(__file__).parent / "golden" / "show_policies"


def _assert_golden_in(text: str, gold_dir: Path, name: str) -> None:
    path = gold_dir / f"{name}.txt"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return
    assert path.exists(), f"missing golden {path} (run with UPDATE_GOLDEN=1)"
    assert text == path.read_text(), f"render drift vs {path.name}"


def _sample_zones() -> tuple[ir.Zone, ...]:
    # A memberless firewall zone, a zone mixing a dual-stack interface with an IPv4 host member,
    # and a zone with an IPv6 host member — RFC 5737/3849 doc ranges only.
    return (
        ir.Zone(name="fw", is_firewall=True),
        ir.Zone(
            name="loc",
            members=(
                ir.ZoneMember(interface="eth1", family=ir.Family.BOTH),
                ir.ZoneMember(interface="eth2", family=ir.Family.IPV4, host="192.0.2.0/24"),
            ),
        ),
        ir.Zone(
            name="net",
            members=(
                ir.ZoneMember(interface="eth0", family=ir.Family.IPV6, host="2001:db8::/32"),
            ),
        ),
    )


def test_render_zones_members_and_families() -> None:
    text = renderer.render_zones(_sample_zones())
    _assert_golden_in(text, _GOLD_ZONES, "zones")
    assert "Zone fw (firewall)" in text  # firewall zone renders with no interface members
    assert "BOTH" in text and "IPV4" in text and "IPV6" in text  # per-member family (ADR-0002)
    assert "192.0.2.0/24" in text and "2001:db8::/32" in text  # host/CIDR members shown


def test_render_zones_empty_is_valid_not_a_crash() -> None:
    text = renderer.render_zones(())
    assert text  # non-empty, no exception
    _assert_golden_in(text, _GOLD_ZONES, "empty")


def _sample_policies() -> tuple[ir.Policy, ...]:
    return (
        ir.Policy(source="loc", dest="net", action="ACCEPT"),
        ir.Policy(source="net", dest="all", action="DROP", log_level="info"),
        ir.Policy(source="all", dest="all", action="REJECT"),
    )


def test_render_policies_matrix_with_log_level() -> None:
    text = renderer.render_policies(_sample_policies())
    _assert_golden_in(text, _GOLD_POLICIES, "policies")
    assert "info" in text  # a policy carrying a log level


def test_render_policies_empty_is_valid_not_a_crash() -> None:
    text = renderer.render_policies(())
    assert text  # non-empty, no exception
    _assert_golden_in(text, _GOLD_POLICIES, "empty")


# ---- show connections: pure conntrack-text renderer (task #412, ADR-0065) ------------------

_FIX_CONN = Path(__file__).parent / "fixtures" / "show_connections"
_GOLD_CONN = Path(__file__).parent / "golden" / "show_connections"


def _load_conn(name: str) -> str:
    return (_FIX_CONN / name).read_text()


def test_render_connections_columnar() -> None:
    text = renderer.render_connections(_load_conn("tracked.txt"))
    _assert_golden_in(text, _GOLD_CONN, "connections")
    # Original-direction tuple, per-family, RFC 5737/3849 doc ranges only.
    assert "ESTABLISHED" in text and "TIME_WAIT" in text  # TCP states surfaced
    assert "192.0.2.2" in text and "2001:db8::2" in text  # v4 and v6 sources
    assert "54321->443" in text  # sport->dport ports column
    assert "203.0.113.9" not in text.split("\n")[0]  # header first, not raw conntrack echo


def test_render_connections_empty_is_valid_not_a_crash() -> None:
    text = renderer.render_connections(_load_conn("empty.txt"))
    assert text  # non-empty banner, no exception
    assert "(no tracked connections)" in text
    _assert_golden_in(text, _GOLD_CONN, "empty")
