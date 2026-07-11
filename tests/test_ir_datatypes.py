import dataclasses

import pytest

from shorewallnf.ir import (
    TPROXY_MARK,
    TPROXY_TABLE_ID,
    ConntrackHelper,
    Family,
    Interface,
    MacroDef,
    MacroRule,
    Nat,
    Policy,
    RateLimit,
    Rule,
    Ruleset,
)

# --- reserved tproxy constants (ADR-0051 Part A) -----------------------------


def test_tproxy_mark_is_the_reserved_top_of_u32() -> None:
    # The single reserved tproxy fwmark: the max 32-bit value, carved out of the top of the
    # provider mark space (ADR-0051 Part A).
    assert TPROXY_MARK == 0xFFFFFFFF


def test_tproxy_table_id_is_the_reserved_top_of_u32() -> None:
    # The reserved tproxy routing-table id: the max 32-bit value, not a kernel-reserved id.
    assert TPROXY_TABLE_ID == 0xFFFFFFFF
    assert TPROXY_TABLE_ID not in {0, 253, 254, 255}

# --- Interface ---------------------------------------------------------------


def test_interface_has_name_and_options() -> None:
    iface = Interface(name="eth0", options=("dhcp", "nosmurfs"))
    assert iface.name == "eth0"
    assert iface.options == ("dhcp", "nosmurfs")


def test_interface_options_default_empty() -> None:
    assert Interface(name="eth0").options == ()


def test_interface_protective_check_fields_default_off() -> None:
    # rpfilter/tcpflags/sfilter all default off so existing constructions are unchanged.
    iface = Interface(name="eth0")
    assert iface.rpfilter is False
    assert iface.tcpflags is False
    assert iface.sfilter == ()


def test_interface_carries_protective_check_fields() -> None:
    iface = Interface(
        name="eth0",
        rpfilter=True,
        tcpflags=True,
        sfilter=("192.0.2.0/24", "2001:db8::/32"),
    )
    assert iface.rpfilter is True
    assert iface.tcpflags is True
    assert iface.sfilter == ("192.0.2.0/24", "2001:db8::/32")


# --- Policy ------------------------------------------------------------------


def test_policy_shape() -> None:
    policy = Policy(source="net", dest="fw", action="DROP", log_level="info")
    assert (policy.source, policy.dest, policy.action, policy.log_level) == (
        "net",
        "fw",
        "DROP",
        "info",
    )


def test_policy_log_level_optional() -> None:
    assert Policy(source="loc", dest="net", action="ACCEPT").log_level is None


# --- Rule (family-aware, ADR-0002) -------------------------------------------


def test_rule_defaults_to_both_families() -> None:
    rule = Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22")
    assert rule.family is Family.BOTH


def test_rule_can_be_scoped_to_a_single_family() -> None:
    rule = Rule(action="ACCEPT", source="net", dest="fw", family=Family.IPV4)
    assert rule.family is Family.IPV4


def test_rule_optional_proto_and_dport() -> None:
    rule = Rule(action="DROP", source="net", dest="fw")
    assert (rule.proto, rule.dport) == (None, None)


# --- RateLimit (rules RATE LIMIT column, #406) -------------------------------


def test_rate_limit_shape() -> None:
    rate = RateLimit(rate=10, interval="minute", burst=20)
    assert (rate.rate, rate.interval, rate.burst) == (10, "minute", 20)


def test_rate_limit_burst_optional() -> None:
    assert RateLimit(rate=10, interval="second").burst is None


def test_rate_limit_is_a_value() -> None:
    assert RateLimit(10, "minute", 20) == RateLimit(10, "minute", 20)


def test_rule_carries_rate_defaulting_none() -> None:
    assert Rule(action="ACCEPT", source="loc", dest="net").rate is None
    rate = RateLimit(rate=10, interval="minute", burst=20)
    assert Rule(action="ACCEPT", source="loc", dest="net", rate=rate).rate is rate


def test_rules_differing_only_in_rate_compare_unequal() -> None:
    base = Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22")
    limited = dataclasses.replace(base, rate=RateLimit(rate=10, interval="minute"))
    assert base != limited


def test_rule_location_stays_out_of_equality_with_rate() -> None:
    rate = RateLimit(rate=10, interval="minute")
    a = Rule(action="ACCEPT", source="loc", dest="net", rate=rate, path="rules", line=1)
    b = Rule(action="ACCEPT", source="loc", dest="net", rate=rate, path="other", line=9)
    assert a == b


# --- Nat (ipv4 by construction, ADR-0002) ------------------------------------


def test_nat_shape() -> None:
    nat = Nat(action="DNAT", source="net", dest="fw", to="192.0.2.5")
    assert (nat.action, nat.source, nat.dest, nat.to) == ("DNAT", "net", "fw", "192.0.2.5")


def test_nat_is_ipv4_by_construction() -> None:
    assert Nat(action="MASQUERADE", source="loc", dest="net").family is Family.IPV4


# --- MacroDef / MacroRule (macro & custom-action definitions, ADR-0020) ------


def test_macro_rule_shape() -> None:
    body = MacroRule(action="ACCEPT", proto="tcp", dport="22", sport="1024:")
    assert (body.action, body.proto, body.dport, body.sport) == (
        "ACCEPT",
        "tcp",
        "22",
        "1024:",
    )


def test_macro_rule_defaults() -> None:
    body = MacroRule(action="DROP")
    assert (body.proto, body.dport, body.sport) == (None, None, None)
    assert body.family is Family.BOTH


def test_macro_rule_can_be_scoped_to_a_single_family() -> None:
    assert MacroRule(action="REJECT", family=Family.IPV6).family is Family.IPV6


def test_macro_def_shape() -> None:
    macro = MacroDef(
        name="Ping",
        body=(MacroRule(action="ACCEPT", proto="icmp"),),
    )
    assert macro.name == "Ping"
    assert macro.body == (MacroRule(action="ACCEPT", proto="icmp"),)
    assert macro.family is Family.BOTH


def test_macro_def_body_defaults_empty() -> None:
    assert MacroDef(name="Empty").body == ()


def test_macro_def_body_is_an_ordered_tuple() -> None:
    macro = MacroDef(
        name="DropInvalid",
        body=(MacroRule(action="DROP"), MacroRule(action="ACCEPT")),
    )
    assert isinstance(macro.body, tuple)
    assert [b.action for b in macro.body] == ["DROP", "ACCEPT"]


# --- ConntrackHelper (family-aware, ADR-0040) --------------------------------


def test_conntrack_helper_shape() -> None:
    helper = ConntrackHelper(
        name="ftp", source="loc", dest="net", proto="tcp", dport="21"
    )
    assert (helper.name, helper.source, helper.dest, helper.proto, helper.dport) == (
        "ftp",
        "loc",
        "net",
        "tcp",
        "21",
    )


def test_conntrack_helper_defaults() -> None:
    helper = ConntrackHelper(name="ftp")
    assert (helper.source, helper.dest, helper.proto, helper.dport) == ("", "", None, None)
    assert helper.family is Family.BOTH


def test_conntrack_helper_can_be_scoped_to_a_single_family() -> None:
    assert ConntrackHelper(name="pptp", family=Family.IPV4).family is Family.IPV4


# --- Rule.action carries a macro/action name (ADR-0020) ----------------------


def test_rule_action_still_accepts_a_builtin_verdict() -> None:
    # Regression: existing verdict rules keep constructing unchanged.
    assert Rule(action="ACCEPT", source="net", dest="fw").action == "ACCEPT"


def test_rule_action_can_carry_a_macro_or_action_name() -> None:
    # ADR-0020: a name in the ACTION column is a plain str, indistinguishable at the
    # type level from a verdict; the resolver stage tells them apart by lookup.
    rule = Rule(action="Ping", source="net", dest="fw")
    assert rule.action == "Ping"


# --- frozen + Ruleset container ----------------------------------------------


@pytest.mark.parametrize(
    ("instance", "field"),
    [
        (Interface(name="eth0"), "name"),
        (Policy(source="net", dest="fw", action="DROP"), "action"),
        (Rule(action="ACCEPT", source="net", dest="fw"), "action"),
        (Nat(action="DNAT", source="net", dest="fw"), "action"),
        (MacroRule(action="ACCEPT"), "action"),
        (MacroDef(name="Ping"), "name"),
        (ConntrackHelper(name="ftp"), "name"),
    ],
)
def test_datatypes_are_frozen(instance: object, field: str) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, field, "x")


def test_ruleset_holds_all_collections_immutably() -> None:
    ruleset = Ruleset(
        interfaces=(Interface(name="eth0"),),
        policies=(Policy(source="net", dest="fw", action="DROP"),),
        rules=(Rule(action="ACCEPT", source="net", dest="fw"),),
        nats=(Nat(action="DNAT", source="net", dest="fw"),),
    )
    assert len(ruleset.interfaces) == len(ruleset.policies) == len(ruleset.rules) == 1
    assert isinstance(ruleset.rules, tuple)
    attr = "rules"  # variable avoids ruff B010 rewriting setattr into a frozen-field assignment
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(ruleset, attr, ())


def test_ruleset_conntrack_helpers_default_empty() -> None:
    assert Ruleset().conntrack_helpers == ()


def test_ruleset_round_trips_conntrack_helpers() -> None:
    helpers = (
        ConntrackHelper(name="ftp", source="loc", dest="net", proto="tcp", dport="21"),
        ConntrackHelper(name="pptp", family=Family.IPV4),
    )
    ruleset = Ruleset(conntrack_helpers=helpers)
    assert ruleset.conntrack_helpers == helpers
    assert isinstance(ruleset.conntrack_helpers, tuple)
    # Value equality (ADR-0001): an equal ruleset built from equal helpers compares equal.
    assert Ruleset(conntrack_helpers=helpers) == ruleset
