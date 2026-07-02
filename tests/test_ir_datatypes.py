import dataclasses

import pytest

from shorewallnf.ir import Family, Interface, Nat, Policy, Rule, Ruleset

# --- Interface ---------------------------------------------------------------


def test_interface_has_name_and_options() -> None:
    iface = Interface(name="eth0", options=("dhcp", "nosmurfs"))
    assert iface.name == "eth0"
    assert iface.options == ("dhcp", "nosmurfs")


def test_interface_options_default_empty() -> None:
    assert Interface(name="eth0").options == ()


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


# --- Nat (ipv4 by construction, ADR-0002) ------------------------------------


def test_nat_shape() -> None:
    nat = Nat(action="DNAT", source="net", dest="fw", to="192.0.2.5")
    assert (nat.action, nat.source, nat.dest, nat.to) == ("DNAT", "net", "fw", "192.0.2.5")


def test_nat_is_ipv4_by_construction() -> None:
    assert Nat(action="MASQUERADE", source="loc", dest="net").family is Family.IPV4


# --- frozen + Ruleset container ----------------------------------------------


@pytest.mark.parametrize(
    ("instance", "field"),
    [
        (Interface(name="eth0"), "name"),
        (Policy(source="net", dest="fw", action="DROP"), "action"),
        (Rule(action="ACCEPT", source="net", dest="fw"), "action"),
        (Nat(action="DNAT", source="net", dest="fw"), "action"),
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
