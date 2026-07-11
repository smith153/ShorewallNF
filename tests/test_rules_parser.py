import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import ConnLimit, Family, Nat, RateLimit, Rule, Zone
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


def test_unsupported_trailing_columns_fail_fast() -> None:
    # Columns past RATE LIMIT (USER/GROUP, MARK, CONNLIMIT, ...) are not supported yet.
    with pytest.raises(ConfigError, match="unsupported"):
        _one("ACCEPT loc net tcp 22 - - 10/min someuser")


def test_unsupported_host_form_fails_fast() -> None:
    with pytest.raises(ConfigError, match="host"):
        _one("ACCEPT loc:not-an-address net")


def test_error_carries_source_location() -> None:
    # A parse error carries the offending row's line; use an unsupported host form (zone-reference
    # integrity moved to the Validator, #323, so an unknown zone no longer fails at parse).
    with pytest.raises(ConfigError) as exc:
        parse_rules(_records("ACCEPT loc net", "ACCEPT loc:not-an-address net"), _ZONES)
    assert exc.value.line == 2


# --- RATE LIMIT column (#406) -------------------------------------------------


def test_rate_limit_with_burst() -> None:
    rule = _one("ACCEPT loc net tcp 22 - - 10/min:20")
    assert rule.rate == RateLimit(rate=10, interval="minute", burst=20)


def test_rate_limit_without_burst() -> None:
    rule = _one("ACCEPT loc net tcp 22 - - 10/sec")
    assert rule.rate == RateLimit(rate=10, interval="second", burst=None)


@pytest.mark.parametrize(
    "shorewall,nft",
    [("sec", "second"), ("min", "minute"), ("hour", "hour"), ("day", "day")],
)
def test_rate_limit_interval_mapping(shorewall: str, nft: str) -> None:
    rule = _one(f"ACCEPT loc net tcp 22 - - 5/{shorewall}")
    assert rule.rate == RateLimit(rate=5, interval=nft, burst=None)


@pytest.mark.parametrize("text", ["ACCEPT loc net tcp 22", "ACCEPT loc net tcp 22 - - -"])
def test_rate_absent_leaves_rate_none(text: str) -> None:
    assert _one(text).rate is None


def test_out_of_scope_origdest_non_dash_still_fails_fast() -> None:
    # The reject keys on ORIGINAL DEST (index 6) being non-`-`, not on field count: a RATE LIMIT
    # value in index 7 is fine, but a value in the intervening out-of-scope column is not.
    # ORIGDEST at index 6 (ACTION SOURCE DEST PROTO DPORT SPORT ORIGDEST RATE); non-`-` there is
    # rejected even though field count is within range and the RATE column (index 7) is valid.
    with pytest.raises(ConfigError, match="ORIGINAL DEST"):
        _one("ACCEPT loc net tcp 22 - 192.0.2.9 10/min")


@pytest.mark.parametrize(
    "spec", ["10min", "abc/min", "10/fortnight", "10/", "10/min:", "10/min:xx"]
)
def test_malformed_rate_spec_fails_fast(spec: str) -> None:
    with pytest.raises(ConfigError, match="rate limit"):
        _one(f"ACCEPT loc net tcp 22 - - {spec}")


def test_malformed_rate_spec_carries_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_rules(_records("ACCEPT loc net", "ACCEPT loc net tcp 22 - - 10/fortnight"), _ZONES)
    assert exc.value.line == 2


@pytest.mark.parametrize("spec", ["weblimit:10/min", "s:10/min", "d:10/min"])
def test_named_or_shared_limiter_rejected_as_unsupported(spec: str) -> None:
    # A `:` before the first `/` is Shorewall's extended/named form (out of scope, YAGNI).
    with pytest.raises(ConfigError, match="named/shared limiters"):
        _one(f"ACCEPT loc net tcp 22 - - {spec}")


# --- CONNLIMIT column (#407) --------------------------------------------------
#
# Columns: ACTION SOURCE DEST PROTO DPORT SPORT ORIGDEST RATE USER MARK CONNLIMIT
# indices:   0      1     2     3    4     5      6      7    8    9     10


def test_connlimit_bare_count_parses() -> None:
    rule = _one("ACCEPT loc net tcp 22 - - - - - 4")
    assert rule.connlimit == ConnLimit(count=4)


@pytest.mark.parametrize(
    "text", ["ACCEPT loc net tcp 22", "ACCEPT loc net tcp 22 - - - - - -"]
)
def test_connlimit_absent_leaves_connlimit_none(text: str) -> None:
    assert _one(text).connlimit is None


def test_rate_and_connlimit_parse_together() -> None:
    rule = _one("ACCEPT loc net tcp 22 - - 10/min - - 4")
    assert rule.rate == RateLimit(rate=10, interval="minute", burst=None)
    assert rule.connlimit == ConnLimit(count=4)


@pytest.mark.parametrize("column,index", [("USER", 8), ("MARK", 9)])
def test_out_of_scope_intervening_column_non_dash_fails_fast(column: str, index: int) -> None:
    # Reaching CONNLIMIT (index 10) needs the intervening USER/GROUP (8) and MARK (9) columns to
    # be `-`; a non-`-` value in one of those unsupported columns fails fast (ADR-0004).
    fields = ["ACCEPT", "loc", "net", "tcp", "22", "-", "-", "-", "-", "-", "4"]
    fields[index] = "x"
    with pytest.raises(ConfigError, match="unsupported"):
        _one(" ".join(fields))


def test_masked_connlimit_rejected_as_unsupported() -> None:
    # The masked/grouped <count>:<mask> per-source form is deferred to #416 (fail fast, ADR-0004).
    with pytest.raises(ConfigError, match="connlimit"):
        _one("ACCEPT loc net tcp 22 - - - - - 4:32")


@pytest.mark.parametrize("spec", ["0", "-4", "abc", "4x"])
def test_malformed_connlimit_fails_fast(spec: str) -> None:
    with pytest.raises(ConfigError, match="connlimit"):
        _one(f"ACCEPT loc net tcp 22 - - - - - {spec}")


def test_malformed_connlimit_carries_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_rules(
            _records("ACCEPT loc net", "ACCEPT loc net tcp 22 - - - - - 0"), _ZONES
        )
    assert exc.value.line == 2


def test_columns_past_connlimit_fail_fast() -> None:
    # TIME and beyond (index 11+) are not supported yet.
    with pytest.raises(ConfigError, match="unsupported trailing"):
        _one("ACCEPT loc net tcp 22 - - - - - 4 timeval")


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


def test_parsed_dnat_carries_source_location() -> None:
    # #316: located diagnostics — the parser stamps the row's path/line onto the Nat.
    (nat,) = _nats("DNAT net loc:192.0.2.5 tcp 22")
    assert (nat.path, nat.line) == ("rules", 1)


def test_dnat_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = Nat(action="DNAT", source="net", dest="loc", to="192.0.2.5", path="rules", line=1)
    b = Nat(action="DNAT", source="net", dest="loc", to="192.0.2.5", path="other", line=9)
    assert a == b
