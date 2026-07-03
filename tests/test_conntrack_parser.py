import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import ConntrackHelper, Family, Zone
from shorewallnf.parser import Record, parse, parse_conntrack
from shorewallnf.preprocessor import SourceLine

ZONES = (Zone(name="fw", is_firewall=True), Zone(name="net"), Zone(name="loc"))


def _records(*texts: str, path: str = "conntrack") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _one(text: str, zones: tuple[Zone, ...] = ZONES) -> ConntrackHelper:
    (helper,) = parse_conntrack(_records(text), zones)
    return helper


# --- registry resolution (defaults) ------------------------------------------


def test_ct_helper_ftp_resolves_registry_defaults() -> None:
    # A bare `CT:helper:ftp` row with no narrowing pulls proto/port + family from the registry.
    assert _one("CT:helper:ftp - - - -") == ConntrackHelper(
        name="ftp",
        source="",
        dest="",
        proto="tcp",
        dport="21",
        family=Family.BOTH,  # ftp is v6-capable (ADR-0040)
    )


def test_ct_helper_tftp_is_v6_capable() -> None:
    # tftp is v6-capable → family follows the registry capability (Family.BOTH).
    assert _one("CT:helper:tftp - -") == ConntrackHelper(
        name="tftp", proto="udp", dport="69", family=Family.BOTH
    )


def test_ct_helper_pptp_is_ipv4_only() -> None:
    # pptp's GRE pairing has no IPv6 conntrack support → Family.IPV4 (ADR-0002).
    assert _one("CT:helper:pptp - -").family is Family.IPV4


# --- per-row narrowing (SOURCE/DEST/PROTO/DPORT) ------------------------------


def test_per_row_proto_and_dport_override_defaults() -> None:
    helper = _one("CT:helper:ftp - - tcp 2121")
    assert (helper.proto, helper.dport) == ("tcp", "2121")


def test_source_and_dest_zone_tokens_captured() -> None:
    helper = _one("CT:helper:ftp net loc")
    assert (helper.source, helper.dest) == ("net", "loc")


def test_v4_host_literal_narrows_family_of_v6_capable_helper() -> None:
    # A v4 host literal in the narrowing columns pins a v6-capable helper to Family.IPV4.
    assert _one("CT:helper:ftp net:192.0.2.0/24 loc").family is Family.IPV4


def test_v6_host_literal_narrows_family() -> None:
    assert _one("CT:helper:ftp net:2001:db8::/32 loc").family is Family.IPV6


# --- fail-fast ---------------------------------------------------------------


def test_unknown_helper_name_fails_fast() -> None:
    with pytest.raises(ConfigError, match="unknown conntrack helper"):
        _one("CT:helper:ftpp - -")


def test_non_ct_helper_action_fails_fast() -> None:
    # notrack / raw-table exemptions are out of scope (epic #200) — reject, don't drop silently.
    with pytest.raises(ConfigError, match="unsupported conntrack action"):
        _one("NOTRACK - -")


def test_v6_literal_on_v4_only_helper_fails_fast() -> None:
    with pytest.raises(ConfigError, match="pptp"):
        _one("CT:helper:pptp net:2001:db8::/32 loc")


def test_unknown_zone_fails_fast() -> None:
    with pytest.raises(ConfigError, match="unknown zone"):
        _one("CT:helper:ftp bogus loc")


def test_unsupported_trailing_columns_fail_fast() -> None:
    # SPORT and beyond aren't modeled in the IR (ADR-0040) — reject rather than drop.
    with pytest.raises(ConfigError, match="unsupported trailing conntrack columns"):
        _one("CT:helper:ftp - - tcp 21 1024")


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_conntrack(_records("CT:helper:ftp - -", "CT:helper:nope - -"), ZONES)
    assert exc.value.line == 2
    assert exc.value.path == "conntrack"
