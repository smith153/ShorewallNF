import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Rule, Zone
from shorewallnf.parser import (
    Record,
    parse,
    parse_config,
    parse_stopped_rules,
)
from shorewallnf.preprocessor import SourceLine, to_source_lines

_ZONES = (
    Zone(name="net"),
    Zone(name="loc"),
    Zone(name="fw", is_firewall=True),
)


def _records(*texts: str, path: str = "stoppedrules") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _streams(**files: str) -> dict[str, list[SourceLine]]:
    return {name: to_source_lines(text, name) for name, text in files.items()}


# --- parse_stopped_rules: reuse the rules grammar, filter-only ---------------


def test_admin_access_row_parses_into_rule_ir() -> None:
    (rule,) = parse_stopped_rules(_records("ACCEPT net fw tcp 22"), _ZONES)
    assert rule == Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22")


def test_rows_carry_source_location() -> None:
    (rule,) = parse_stopped_rules(_records("ACCEPT net fw"), _ZONES)
    assert (rule.path, rule.line) == ("stoppedrules", 1)


def test_empty_input_yields_empty_admin_set() -> None:
    assert parse_stopped_rules(_records(), _ZONES) == ()


def test_ipv4_host_infers_ipv4_family() -> None:
    (rule,) = parse_stopped_rules(_records("ACCEPT net:192.0.2.0/24 fw"), _ZONES)
    assert rule.family is Family.IPV4


def test_ipv6_host_infers_ipv6_family() -> None:
    (rule,) = parse_stopped_rules(_records("ACCEPT net:2001:db8::/32 fw"), _ZONES)
    assert rule.family is Family.IPV6


def test_malformed_row_fails_fast_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_stopped_rules(_records("ACCEPT net fw", "ACCEPT"), _ZONES)
    assert exc.value.path == "stoppedrules"
    assert exc.value.line == 2


def test_dnat_row_is_rejected_with_location() -> None:
    # stoppedrules is admin-access filter traffic only; a DNAT row has no meaning here.
    with pytest.raises(ConfigError) as exc:
        parse_stopped_rules(
            _records("ACCEPT net fw tcp 22", "DNAT net loc:192.0.2.10 tcp 80"),
            _ZONES,
        )
    assert exc.value.line == 2
    assert "DNAT" in str(exc.value)


# --- parse_config: surfaced on a distinct Ruleset field ----------------------


def test_stopped_rules_surface_on_distinct_field() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\n",
            rules="ACCEPT net fw tcp 80\n",
            stoppedrules="ACCEPT net:192.0.2.0/24 fw tcp 22\n",
        )
    )
    assert ruleset.stopped_rules == (
        Rule(
            action="ACCEPT",
            source="net:192.0.2.0/24",
            dest="fw",
            proto="tcp",
            dport="22",
            family=Family.IPV4,
        ),
    )
    # The stopped set is not merged into the ordinary filter rules.
    assert [r.dport for r in ruleset.rules] == ["80"]
    assert ruleset.stopped_rules[0].family is Family.IPV4


def test_absent_stoppedrules_yields_empty_field() -> None:
    ruleset = parse_config(_streams(zones="fw firewall\nnet ipv4\n"))
    assert ruleset.stopped_rules == ()
