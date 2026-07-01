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
