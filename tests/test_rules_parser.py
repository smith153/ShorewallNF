import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Rule, Zone
from shorewallnf.parser import Record, parse, parse_rules
from shorewallnf.preprocessor import SourceLine

_ZONES = (
    Zone(name="net"),
    Zone(name="loc"),
    Zone(name="dmz"),
    Zone(name="fw", is_firewall=True),
)


def _records(*texts: str, path: str = "rules") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _one(text: str) -> Rule:
    (rule,) = parse_rules(_records(text), _ZONES)
    return rule


# --- basic shape --------------------------------------------------------------


def test_minimal_rule_action_source_dest() -> None:
    assert _one("ACCEPT loc net") == Rule(action="ACCEPT", source="loc", dest="net")


@pytest.mark.parametrize("action", ["ACCEPT", "DROP", "REJECT"])
def test_builtin_actions(action: str) -> None:
    assert _one(f"{action} loc net").action == action


def test_proto_and_dest_port() -> None:
    rule = _one("ACCEPT loc net tcp 22")
    assert (rule.proto, rule.dport, rule.sport) == ("tcp", "22", None)


def test_source_port_column() -> None:
    rule = _one("ACCEPT loc net udp 53 1024")
    assert (rule.proto, rule.dport, rule.sport) == ("udp", "53", "1024")


def test_dash_columns_are_none() -> None:
    rule = _one("ACCEPT loc net - - 1024")  # no proto, no dport, only sport
    assert (rule.proto, rule.dport, rule.sport) == (None, None, "1024")


# --- ports: single / comma-list / range, verbatim on both columns -------------


def test_port_comma_list_preserved() -> None:
    assert _one("ACCEPT loc net tcp 8728,8729").dport == "8728,8729"


def test_port_range_preserved() -> None:
    assert _one("ACCEPT loc net tcp 49160:49300").dport == "49160:49300"


def test_range_on_source_port_column() -> None:
    assert _one("ACCEPT loc net udp - 49160:49300").sport == "49160:49300"


# --- zone:host narrowing + family inference (ADR-0002) ------------------------


def test_bare_zones_infer_family_both() -> None:
    assert _one("ACCEPT loc net tcp 22").family is Family.BOTH


def test_ipv4_host_pins_ipv4_and_is_stored_verbatim() -> None:
    rule = _one("ACCEPT loc:10.36.36.166 fw tcp 22")
    assert rule.source == "loc:10.36.36.166"
    assert rule.family is Family.IPV4


def test_firewall_host_narrowing() -> None:
    assert _one("ACCEPT net fw:10.36.36.1 tcp 22").family is Family.IPV4


def test_ipv6_host_pins_ipv6_split_on_first_colon() -> None:
    rule = _one("ACCEPT loc:2001:db8::1 net")
    assert rule.source == "loc:2001:db8::1"
    assert rule.family is Family.IPV6


def test_ipv4_cidr_host() -> None:
    assert _one("ACCEPT loc:10.36.36.0/24 net").family is Family.IPV4


def test_icmp_proto_pins_ipv4() -> None:
    assert _one("ACCEPT loc net icmp").family is Family.IPV4


def test_ipv6_icmp_proto_pins_ipv6() -> None:
    assert _one("ACCEPT loc net ipv6-icmp").family is Family.IPV6


def test_mixed_family_literals_fail_fast() -> None:
    with pytest.raises(ConfigError, match="famil"):
        _one("ACCEPT loc:10.0.0.1 net:2001:db8::1")


def test_host_family_conflicts_with_proto_family() -> None:
    with pytest.raises(ConfigError, match="famil"):
        _one("ACCEPT loc:10.0.0.1 net ipv6-icmp")


# --- ?SECTION attachment ------------------------------------------------------


def test_rule_before_any_section_has_none() -> None:
    assert _one("ACCEPT loc net").section is None


def test_section_attached_to_following_rules() -> None:
    rules = parse_rules(
        _records("?SECTION ESTABLISHED", "ACCEPT loc net", "?SECTION NEW", "DROP net loc"),
        _ZONES,
    )
    assert [(r.action, r.section) for r in rules] == [
        ("ACCEPT", "ESTABLISHED"),
        ("DROP", "NEW"),
    ]


# --- fail-fast ----------------------------------------------------------------


def test_unknown_action_fails_fast() -> None:
    with pytest.raises(ConfigError, match="action"):
        _one("BOGUS loc net")


def test_missing_dest_fails_fast_with_location() -> None:
    with pytest.raises(ConfigError, match="dest"):
        _one("ACCEPT loc")


def test_unknown_zone_fails_fast() -> None:
    with pytest.raises(ConfigError, match="zone"):
        _one("ACCEPT bogus net")


def test_unsupported_trailing_columns_fail_fast() -> None:
    # A 7th column (ORIGINAL DEST / RATE LIMIT / USER / MARK ...) is not supported yet.
    with pytest.raises(ConfigError, match="unsupported"):
        _one("ACCEPT loc net tcp 22 - 10.0.0.9")


def test_unsupported_host_form_fails_fast() -> None:
    with pytest.raises(ConfigError, match="host"):
        _one("ACCEPT loc:not-an-address net")


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_rules(_records("ACCEPT loc net", "BOGUS loc net"), _ZONES)
    assert exc.value.line == 2
