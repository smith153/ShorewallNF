"""Resolver stage tests (ADR-0020, #184).

The pure IR→IR transform that expands a macro/action-invoking ``Rule`` into the verdict rules
of its body, narrowing each by the call site, and fails fast on an unknown name or an empty
narrowing intersection.
"""

from __future__ import annotations

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, MacroDef, MacroRule, Rule, Ruleset
from shorewallnf.resolver import resolve


def _rs(*rules: Rule, actions: dict[str, MacroDef] | None = None) -> Ruleset:
    return Ruleset(rules=rules, actions=actions or {})


# --- AC1: macro/action expansion (built-in + site), body order --------------


def test_builtin_macro_expands_in_body_order() -> None:
    # `Web` is a built-in port-group macro: tcp 80 then tcp 443, in that order.
    out = resolve(_rs(Rule(action="Web", source="net", dest="fw")))
    assert out.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="80"),
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="443"),
    )


def test_site_action_expands() -> None:
    macro = MacroDef(
        name="Svc",
        body=(
            MacroRule(action="ACCEPT", proto="tcp", dport="22"),
            MacroRule(action="DROP", proto="udp", dport="53"),
        ),
    )
    out = resolve(_rs(Rule(action="Svc", source="loc", dest="fw"), actions={"Svc": macro}))
    assert out.rules == (
        Rule(action="ACCEPT", source="loc", dest="fw", proto="tcp", dport="22"),
        Rule(action="DROP", source="loc", dest="fw", proto="udp", dport="53"),
    )


def test_verdict_rules_pass_through_unchanged() -> None:
    rules = (
        Rule(action="ACCEPT", source="loc", dest="net"),
        Rule(action="DROP", source="net", dest="fw", proto="tcp", dport="23"),
        Rule(action="REJECT", source="net", dest="all"),
    )
    assert resolve(_rs(*rules)).rules == rules


def test_expansion_preserves_call_site_section() -> None:
    # The section rides along so the validator's ESTABLISHED/RELATED check still sees it.
    out = resolve(_rs(Rule(action="Web", source="net", dest="fw", section="NEW")))
    assert all(r.section == "NEW" for r in out.rules)


# --- AC2: call-site narrowing = per-field intersection ----------------------


def test_narrowing_takes_body_value_when_call_site_unconstrained() -> None:
    # ACCEPT net fw invoking body row ACCEPT - tcp 22 -> ACCEPT net fw tcp 22.
    macro = MacroDef(name="Ssh", body=(MacroRule(action="ACCEPT", proto="tcp", dport="22"),))
    out = resolve(_rs(Rule(action="Ssh", source="net", dest="fw"), actions={"Ssh": macro}))
    assert out.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22"),
    )


def test_narrowing_takes_call_site_value_when_body_unconstrained() -> None:
    macro = MacroDef(name="A", body=(MacroRule(action="ACCEPT"),))
    call = Rule(action="A", source="net", dest="fw", proto="tcp", dport="22")
    out = resolve(_rs(call, actions={"A": macro}))
    assert out.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22"),
    )


def test_narrowing_equal_values_collapse() -> None:
    macro = MacroDef(name="A", body=(MacroRule(action="ACCEPT", proto="tcp", dport="80"),))
    call = Rule(action="A", source="net", dest="fw", proto="tcp", dport="80")
    out = resolve(_rs(call, actions={"A": macro}))
    assert out.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="80"),
    )


def test_narrowing_disjoint_ports_fail_fast() -> None:
    macro = MacroDef(name="A", body=(MacroRule(action="ACCEPT", proto="tcp", dport="443"),))
    with pytest.raises(ConfigError) as err:
        resolve(
            _rs(
                Rule(action="A", source="net", dest="fw", proto="tcp", dport="80"),
                actions={"A": macro},
            )
        )
    assert "A" in str(err.value)


def test_narrowing_disjoint_proto_fail_fast() -> None:
    macro = MacroDef(name="A", body=(MacroRule(action="ACCEPT", proto="udp"),))
    with pytest.raises(ConfigError):
        resolve(
            _rs(Rule(action="A", source="net", dest="fw", proto="tcp"), actions={"A": macro})
        )


def test_family_intersection_body_proto_pins_family() -> None:
    # A both-family call site invoking an icmp body row yields an IPv4-scoped expanded rule.
    macro = MacroDef(
        name="P", body=(MacroRule(action="ACCEPT", proto="icmp", family=Family.IPV4),),
        family=Family.IPV4,
    )
    out = resolve(_rs(Rule(action="P", source="net", dest="fw"), actions={"P": macro}))
    assert out.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="icmp", family=Family.IPV4),
    )


def test_family_disjoint_fails_fast() -> None:
    macro = MacroDef(
        name="P", body=(MacroRule(action="ACCEPT", proto="ipv6-icmp", family=Family.IPV6),),
        family=Family.IPV6,
    )
    with pytest.raises(ConfigError):
        resolve(
            _rs(
                Rule(action="P", source="net", dest="fw", proto="icmp", family=Family.IPV4),
                actions={"P": macro},
            )
        )


# --- AC3: unknown/malformed name fails fast, identified by rule content ------


def test_unknown_action_fails_fast_by_rule_content() -> None:
    with pytest.raises(ConfigError) as err:
        resolve(_rs(Rule(action="Bogus", source="net", dest="fw", proto="tcp", dport="22")))
    message = str(err.value)
    assert "Bogus" in message
    for field in ("net", "fw", "tcp", "22"):
        assert field in message


def test_resolution_stops_at_first_unknown() -> None:
    with pytest.raises(ConfigError) as err:
        resolve(
            _rs(
                Rule(action="First", source="net", dest="fw"),
                Rule(action="Second", source="loc", dest="net"),
            )
        )
    assert "First" in str(err.value) and "Second" not in str(err.value)


# --- #195: source location threads through expansion and into errors --------


def test_expansion_preserves_call_site_source_location() -> None:
    # Each expanded verdict rule inherits the invoking rule's path:line so post-expansion
    # validator errors still cite the originating config line.
    out = resolve(_rs(Rule(action="Web", source="net", dest="fw", path="rules", line=9)))
    assert [(r.path, r.line) for r in out.rules] == [("rules", 9), ("rules", 9)]


def test_unknown_action_error_cites_path_line() -> None:
    with pytest.raises(ConfigError) as err:
        resolve(_rs(Rule(action="Bogus", source="net", dest="fw", path="rules", line=4)))
    assert str(err.value).startswith("rules:4: ")


def test_unsatisfiable_narrowing_error_cites_path_line() -> None:
    site = MacroDef(name="Svc", body=(MacroRule(action="ACCEPT", proto="tcp", dport="80"),))
    call = Rule(action="Svc", source="net", dest="fw", dport="443", path="rules", line=5)
    with pytest.raises(ConfigError) as err:
        resolve(_rs(call, actions={"Svc": site}))
    assert str(err.value).startswith("rules:5: ")


# --- AC4: site-action precedence overrides a built-in of the same name ------


def test_site_action_overrides_builtin_of_same_name() -> None:
    # Redefine `Web` at the site with a single-port body; the site definition must win.
    site = MacroDef(name="Web", body=(MacroRule(action="ACCEPT", proto="tcp", dport="8080"),))
    out = resolve(_rs(Rule(action="Web", source="net", dest="fw"), actions={"Web": site}))
    assert out.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="8080"),
    )
