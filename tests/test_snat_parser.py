import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Nat
from shorewallnf.parser import Record, parse, parse_snat
from shorewallnf.preprocessor import SourceLine


def _records(*texts: str, path: str = "snat") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _one(text: str) -> Nat:
    (nat,) = parse_snat(_records(text))
    return nat


# --- MASQUERADE / SNAT basic shape -------------------------------------------


def test_masquerade_row_builds_a_nat_entry() -> None:
    assert _one("MASQUERADE 10.0.0.0/8 eth0") == Nat(
        action="MASQUERADE",
        source_nets="10.0.0.0/8",
        out_interface="eth0",
        snat_to=None,
        family=Family.IPV4,
    )


def test_snat_carries_the_explicit_source_address() -> None:
    assert _one("SNAT(203.0.113.5) 10.0.0.0/8 eth0") == Nat(
        action="SNAT",
        source_nets="10.0.0.0/8",
        out_interface="eth0",
        snat_to="203.0.113.5",
        family=Family.IPV4,
    )


def test_masquerade_leaves_dnat_columns_unset() -> None:
    nat = _one("MASQUERADE 10.0.0.0/8 eth0")
    assert (nat.source, nat.dest, nat.to, nat.proto, nat.dport) == ("", "", None, None, None)


# --- source-net list preserved verbatim (multi-CIDR) -------------------------


def test_multi_cidr_source_list_preserved_verbatim() -> None:
    nat = _one("MASQUERADE 10.0.0.0/8,192.0.2.0/24,203.0.113.0/24 eth0")
    assert nat.source_nets == "10.0.0.0/8,192.0.2.0/24,203.0.113.0/24"


def test_snat_multi_cidr_source_list_preserved_verbatim() -> None:
    nat = _one("SNAT(203.0.113.5) 192.0.2.0/24,198.51.100.0/24 eth1")
    assert nat.source_nets == "192.0.2.0/24,198.51.100.0/24"
    assert nat.snat_to == "203.0.113.5"


def test_backslash_continued_row_is_one_nat() -> None:
    # A row continued across physical lines joins into a single logical record (parser scaffold).
    (nat,) = parse_snat(_records("MASQUERADE 10.0.0.0/8 \\", "eth0"))
    assert nat == Nat(
        action="MASQUERADE", source_nets="10.0.0.0/8", out_interface="eth0", family=Family.IPV4
    )


# --- family is IPv4 by construction (ADR-0002) -------------------------------


@pytest.mark.parametrize("row", ["MASQUERADE 10.0.0.0/8 eth0", "SNAT(203.0.113.5) 10.0.0.0/8 eth0"])
def test_source_nat_is_always_ipv4(row: str) -> None:
    assert _one(row).family is Family.IPV4


# --- fail-fast ---------------------------------------------------------------


def test_unsupported_trailing_columns_fail_fast() -> None:
    # PROTO/PORT/IPSEC/MARK/PROBABILITY narrowing is out of MVP scope (#76).
    with pytest.raises(ConfigError, match="unsupported"):
        _one("MASQUERADE 10.0.0.0/8 eth0 tcp")


def test_unknown_action_fails_fast() -> None:
    with pytest.raises(ConfigError, match="action"):
        _one("BOGUS 10.0.0.0/8 eth0")


def test_bare_snat_without_address_fails_fast() -> None:
    with pytest.raises(ConfigError, match="SNAT"):
        _one("SNAT 10.0.0.0/8 eth0")


def test_empty_snat_address_fails_fast() -> None:
    with pytest.raises(ConfigError, match="SNAT"):
        _one("SNAT() 10.0.0.0/8 eth0")


def test_missing_egress_interface_fails_fast() -> None:
    with pytest.raises(ConfigError, match="interface"):
        _one("MASQUERADE 10.0.0.0/8")


def test_missing_source_fails_fast() -> None:
    with pytest.raises(ConfigError, match="source"):
        _one("MASQUERADE")


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_snat(_records("MASQUERADE 10.0.0.0/8 eth0", "BOGUS 10.0.0.0/8 eth0"))
    assert exc.value.line == 2
    assert exc.value.path == "snat"


def test_parsed_snat_carries_source_location() -> None:
    # #316: located diagnostics — the parser stamps the row's path/line onto the IR.
    assert (_one("MASQUERADE 10.0.0.0/8 eth0").path,
            _one("MASQUERADE 10.0.0.0/8 eth0").line) == ("snat", 1)


def test_snat_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = Nat(action="MASQUERADE", source_nets="10.0.0.0/8", out_interface="eth0",
            family=Family.IPV4, path="snat", line=1)
    b = Nat(action="MASQUERADE", source_nets="10.0.0.0/8", out_interface="eth0",
            family=Family.IPV4, path="other", line=9)
    assert a == b
