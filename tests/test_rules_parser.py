import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Nat, Rule, Zone
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
    (rule,) = parse_rules(_records(text), _ZONES).rules
    return rule


# --- basic shape --------------------------------------------------------------


def test_minimal_rule_action_source_dest() -> None:
    assert _one("ACCEPT loc net") == Rule(action="ACCEPT", source="loc", dest="net")


@pytest.mark.parametrize("action", ["ACCEPT", "DROP", "REJECT"])
def test_builtin_actions(action: str) -> None:
    assert _one(f"{action} loc net").action == action


def test_rule_carries_source_location() -> None:
    # #195: the parser threads the record's path and 1-based line onto the Rule so
    # downstream IR-stage errors can cite path:line.
    records = _records("ACCEPT loc net", "DROP loc net", path="rules")
    rules = parse_rules(records, _ZONES).rules
    assert (rules[0].path, rules[0].line) == ("rules", 1)
    assert (rules[1].path, rules[1].line) == ("rules", 2)


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


# --- proto normalised to canonical lowercase (#134) ---------------------------


@pytest.mark.parametrize("proto", ["tcp", "TCP", "Tcp", "tCp"])
def test_proto_normalised_to_lowercase(proto: str) -> None:
    assert _one(f"ACCEPT loc net {proto} 22").proto == "tcp"


def test_uppercase_icmp_normalised_and_still_pins_ipv4() -> None:
    rule = _one("ACCEPT loc net ICMP")
    assert rule.proto == "icmp"
    assert rule.family is Family.IPV4


def test_mixedcase_ipv6_icmp_normalised_and_still_pins_ipv6() -> None:
    rule = _one("ACCEPT loc net IPv6-ICMP")
    assert rule.proto == "ipv6-icmp"
    assert rule.family is Family.IPV6


# --- zone:host narrowing + family inference (ADR-0002) ------------------------


def test_bare_zones_infer_family_both() -> None:
    assert _one("ACCEPT loc net tcp 22").family is Family.BOTH


def test_ipv4_host_pins_ipv4_and_is_stored_verbatim() -> None:
    rule = _one("ACCEPT loc:198.51.100.166 fw tcp 22")
    assert rule.source == "loc:198.51.100.166"
    assert rule.family is Family.IPV4


def test_firewall_host_narrowing() -> None:
    assert _one("ACCEPT net fw:198.51.100.1 tcp 22").family is Family.IPV4


def test_ipv6_host_pins_ipv6_split_on_first_colon() -> None:
    rule = _one("ACCEPT loc:2001:db8::1 net")
    assert rule.source == "loc:2001:db8::1"
    assert rule.family is Family.IPV6


def test_ipv4_cidr_host() -> None:
    assert _one("ACCEPT loc:198.51.100.0/24 net").family is Family.IPV4


def test_icmp_proto_pins_ipv4() -> None:
    assert _one("ACCEPT loc net icmp").family is Family.IPV4


def test_ipv6_icmp_proto_pins_ipv6() -> None:
    assert _one("ACCEPT loc net ipv6-icmp").family is Family.IPV6


def test_mixed_family_literals_fail_fast() -> None:
    with pytest.raises(ConfigError, match="famil"):
        _one("ACCEPT loc:192.0.2.1 net:2001:db8::1")


def test_host_family_conflicts_with_proto_family() -> None:
    with pytest.raises(ConfigError, match="famil"):
        _one("ACCEPT loc:192.0.2.1 net ipv6-icmp")


# --- ?SECTION attachment ------------------------------------------------------


def test_rule_before_any_section_has_none() -> None:
    assert _one("ACCEPT loc net").section is None


def test_section_attached_to_following_rules() -> None:
    rules = parse_rules(
        _records("?SECTION ESTABLISHED", "ACCEPT loc net", "?SECTION NEW", "DROP net loc"),
        _ZONES,
    ).rules
    assert [(r.action, r.section) for r in rules] == [
        ("ACCEPT", "ESTABLISHED"),
        ("DROP", "NEW"),
    ]


# --- fail-fast ----------------------------------------------------------------


def test_non_verdict_action_passes_through_as_macro_name() -> None:
    # The parser is macro-unaware (ADR-0020 §2): a non-verdict ACTION is stored verbatim as a
    # possible macro/action name; the resolver (#184) tells names from verdicts by lookup and
    # fails fast on an unknown one, so the parser no longer rejects it.
    assert _one("Web loc net") == Rule(action="Web", source="loc", dest="net")


def test_missing_dest_fails_fast_with_location() -> None:
    with pytest.raises(ConfigError, match="dest"):
        _one("ACCEPT loc")


def test_unknown_zone_fails_fast() -> None:
    with pytest.raises(ConfigError, match="zone"):
        _one("ACCEPT bogus net")


def test_unsupported_trailing_columns_fail_fast() -> None:
    # A 7th column (ORIGINAL DEST / RATE LIMIT / USER / MARK ...) is not supported yet.
    with pytest.raises(ConfigError, match="unsupported"):
        _one("ACCEPT loc net tcp 22 - 192.0.2.9")


def test_unsupported_host_form_fails_fast() -> None:
    with pytest.raises(ConfigError, match="host"):
        _one("ACCEPT loc:not-an-address net")


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_rules(_records("ACCEPT loc net", "ACCEPT bogus net"), _ZONES)
    assert exc.value.line == 2


# --- DNAT rows build Nat entries (task #142, epic #75) ------------------------


def _nats(*texts: str) -> tuple[Nat, ...]:
    return parse_rules(_records(*texts), _ZONES).nats


def test_dnat_action_builds_a_nat_entry_not_a_rule() -> None:
    parsed = parse_rules(_records("DNAT net loc:192.0.2.5 tcp 22"), _ZONES)
    assert parsed.rules == ()
    assert parsed.nats == (
        Nat(
            action="DNAT", source="net", dest="loc", to="192.0.2.5",
            proto="tcp", dport="22", family=Family.IPV4,
        ),
    )


def test_dnat_target_port_remap_is_captured_in_to() -> None:
    (nat,) = _nats("DNAT net loc:192.0.2.5:8022 tcp 22")
    assert (nat.to, nat.dport) == ("192.0.2.5:8022", "22")


def test_dnat_port_range() -> None:
    assert _nats("DNAT net loc:192.0.2.5 tcp 49160:49300")[0].dport == "49160:49300"


def test_dnat_v6_target_infers_ipv6() -> None:
    (nat,) = _nats("DNAT net loc:2001:db8::5 tcp 443")
    assert nat.family is Family.IPV6
    assert nat.to == "2001:db8::5"


def test_dnat_proto_is_lowercased() -> None:
    assert _nats("DNAT net loc:192.0.2.5 TCP 80")[0].proto == "tcp"


def test_filter_rules_and_dnat_are_separated() -> None:
    parsed = parse_rules(
        _records("ACCEPT loc net tcp 22", "DNAT net loc:192.0.2.5 tcp 80"), _ZONES
    )
    assert len(parsed.rules) == 1 and parsed.rules[0].action == "ACCEPT"
    assert len(parsed.nats) == 1 and parsed.nats[0].action == "DNAT"


def test_dnat_without_target_host_fails_fast() -> None:
    with pytest.raises(ConfigError, match="host"):
        _nats("DNAT net loc tcp 22")


def test_dnat_unknown_target_zone_fails_fast() -> None:
    with pytest.raises(ConfigError, match="zone"):
        _nats("DNAT net bogus:192.0.2.5 tcp 22")
