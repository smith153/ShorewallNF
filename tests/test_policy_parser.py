import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Policy, Zone
from shorewallnf.parser import Record, parse, parse_policies
from shorewallnf.preprocessor import SourceLine

_ZONES = (
    Zone(name="net"),
    Zone(name="loc"),
    Zone(name="dmz"),
    Zone(name="fw", is_firewall=True),
)


def _records(*texts: str, path: str = "policy") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def test_basic_policy() -> None:
    (policy,) = parse_policies(_records("loc net ACCEPT"), _ZONES)
    assert policy == Policy(source="loc", dest="net", action="ACCEPT")


def test_policy_with_log_level() -> None:
    (policy,) = parse_policies(_records("dmz loc REJECT info"), _ZONES)
    assert policy == Policy(source="dmz", dest="loc", action="REJECT", log_level="info")


def test_all_wildcard_source_and_dest() -> None:
    (policy,) = parse_policies(_records("all all REJECT info"), _ZONES)
    assert (policy.source, policy.dest) == ("all", "all")


def test_firewall_zone_accepted() -> None:
    (policy,) = parse_policies(_records("fw net ACCEPT"), _ZONES)
    assert policy.source == "fw"


def test_representative_policy_file() -> None:
    records = _records(
        "loc net ACCEPT", "fw net ACCEPT", "net all DROP info", "all all REJECT info"
    )
    assert [
        (p.source, p.dest, p.action, p.log_level) for p in parse_policies(records, _ZONES)
    ] == [
        ("loc", "net", "ACCEPT", None),
        ("fw", "net", "ACCEPT", None),
        ("net", "all", "DROP", "info"),
        ("all", "all", "REJECT", "info"),
    ]


def test_unknown_action_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net ACCEPT", "loc dmz BOGUS"), _ZONES)
    assert exc.value.line == 2
    assert "BOGUS" in str(exc.value)


def test_unknown_zone_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc badzone ACCEPT"), _ZONES)
    assert "badzone" in str(exc.value)


def test_missing_action_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net"), _ZONES)
    assert "action" in str(exc.value)


def test_unsupported_trailing_columns_rejected() -> None:
    # Shorewall's policy file has further columns (LIMIT:BURST, CONNLIMIT); rather than
    # silently drop them, reject until supported (#94, fail-fast).
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("net all DROP info 10/sec:20"), _ZONES)
    assert exc.value.line == 1


def test_four_columns_still_accepted() -> None:
    (policy,) = parse_policies(_records("net all DROP info"), _ZONES)
    assert policy.log_level == "info"


# --- log-level validation (#117) ---------------------------------------------


@pytest.mark.parametrize(
    "level", ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug", "audit"]
)
def test_valid_nft_log_levels_accepted(level: str) -> None:
    (policy,) = parse_policies(_records(f"net all DROP {level}"), _ZONES)
    assert policy.log_level == level


@pytest.mark.parametrize(
    "bad",
    ["warning", "error", "panic", "6", "NFLOG", "ULOG", "Info"],
)
def test_unsupported_log_level_fails_fast(bad: str) -> None:
    # syslog spellings, numeric levels, NFLOG/ULOG targets, and non-lowercase spellings
    # aren't nft `log level` values — reject rather than emit an invalid ruleset (ADR-0004).
    with pytest.raises(ConfigError, match="log level"):
        parse_policies(_records(f"net all DROP {bad}"), _ZONES)


def test_unsupported_log_level_error_is_located() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net ACCEPT", "net all DROP warning"), _ZONES)
    assert exc.value.line == 2


def test_parsed_policy_carries_source_location() -> None:
    # #316: located diagnostics — the parser stamps the row's path/line onto the IR.
    (policy,) = parse_policies(_records("loc net ACCEPT"), _ZONES)
    assert (policy.path, policy.line) == ("policy", 1)


def test_policy_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = Policy(source="loc", dest="net", action="ACCEPT", path="policy", line=1)
    b = Policy(source="loc", dest="net", action="ACCEPT", path="other", line=9)
    assert a == b
