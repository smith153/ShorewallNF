"""Tests for the ``providers`` file parser (epic #204, task #232, ADR-0002).

A ``providers`` row is ``NAME NUMBER MARK INTERFACE GATEWAY [OPTIONS]``: the provider name, its
routing-table number, the fwmark steered into that table, the egress interface, the next-hop
gateway, and an optional comma-separated options list. Rows parse into family-aware
:class:`~shorewallnf.ir.Provider` IR — the family follows the gateway literal (v4/v6), defaulting
to dual-stack for a non-literal gateway (e.g. ``detect``). Malformed rows fail fast (ADR-0004).
Cross-checking interface references is a later task (#233); this parser only shapes the IR.
"""

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Provider
from shorewallnf.parser import Record, parse, parse_config, parse_providers
from shorewallnf.preprocessor import SourceLine, to_source_lines


def _records(*texts: str, path: str = "providers") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _one(text: str) -> Provider:
    (provider,) = parse_providers(_records(text))
    return provider


# --- basic shape -------------------------------------------------------------


def test_row_builds_a_provider_entry() -> None:
    assert _one("wan 1 1 eth0 192.0.2.1") == Provider(
        name="wan",
        number=1,
        mark=1,
        interface="eth0",
        gateway="192.0.2.1",
        options=(),
        family=Family.IPV4,
    )


def test_options_column_is_split_into_a_tuple() -> None:
    assert _one("wan 1 1 eth0 192.0.2.1 track,balance").options == ("track", "balance")


def test_absent_options_column_is_an_empty_tuple() -> None:
    assert _one("wan 1 1 eth0 192.0.2.1").options == ()


def test_two_providers_preserve_file_order() -> None:
    providers = parse_providers(
        _records("wan1 1 1 eth0 192.0.2.1", "wan2 2 2 eth1 198.51.100.1")
    )
    assert [p.name for p in providers] == ["wan1", "wan2"]
    assert providers[1] == Provider(
        name="wan2", number=2, mark=2, interface="eth1", gateway="198.51.100.1",
        family=Family.IPV4,
    )


# --- family inference from the gateway (ADR-0002) ----------------------------


def test_ipv4_gateway_scopes_provider_to_ipv4() -> None:
    assert _one("wan 1 1 eth0 192.0.2.1").family is Family.IPV4


def test_ipv6_gateway_scopes_provider_to_ipv6() -> None:
    assert _one("wan 1 1 eth0 2001:db8::1").family is Family.IPV6


def test_non_literal_gateway_leaves_provider_dual_stack() -> None:
    # A `detect` gateway (auto-detected from the interface) carries no family literal.
    assert _one("wan 1 1 eth0 detect").family is Family.BOTH


def test_mark_and_number_accept_hex() -> None:
    provider = _one("wan 1 0x100 eth0 192.0.2.1")
    assert provider.mark == 256 and provider.number == 1


# --- fail fast (ADR-0004) ----------------------------------------------------


def test_missing_required_column_fails_fast() -> None:
    with pytest.raises(ConfigError, match="gateway"):
        _one("wan 1 1 eth0")  # no gateway


def test_non_integer_number_fails_fast() -> None:
    with pytest.raises(ConfigError, match="number"):
        _one("wan main 1 eth0 192.0.2.1")


def test_non_integer_mark_fails_fast() -> None:
    with pytest.raises(ConfigError, match="mark"):
        _one("wan 1 notamark eth0 192.0.2.1")


def test_unsupported_trailing_columns_fail_fast() -> None:
    with pytest.raises(ConfigError, match="trailing"):
        _one("wan 1 1 eth0 192.0.2.1 track extra")


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_providers(_records("wan 1 1 eth0 192.0.2.1", "bad 2 x eth1 198.51.100.1"))
    assert exc.value.line == 2
    assert exc.value.path == "providers"


# --- parse_config wiring -----------------------------------------------------


def test_parse_config_carries_providers_into_the_ruleset() -> None:
    ruleset = parse_config(
        {"providers": to_source_lines("wan 1 1 eth0 192.0.2.1\n", "providers")}
    )
    assert ruleset.providers == (
        Provider(
            name="wan", number=1, mark=1, interface="eth0", gateway="192.0.2.1",
            family=Family.IPV4,
        ),
    )


def test_parsed_provider_carries_source_location() -> None:
    # #251: located diagnostics — the parser stamps the row's path/line onto the IR.
    assert (_one("wan 1 1 eth0 192.0.2.1").path, _one("wan 1 1 eth0 192.0.2.1").line) == (
        "providers", 1,
    )


def test_provider_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = Provider(name="wan", number=1, mark=1, interface="eth0", gateway="192.0.2.1",
                 path="providers", line=1)
    b = Provider(name="wan", number=1, mark=1, interface="eth0", gateway="192.0.2.1",
                 path="other", line=9)
    assert a == b
