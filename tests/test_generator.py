import json
from pathlib import Path
from typing import Any

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.generator import generate
from shorewallnf.ir import Family, Policy, Rule, Ruleset, Zone, ZoneMember
from tests.golden_harness import assert_golden

POLICY_GOLDEN = Path(__file__).parent / "golden" / "policy_default_rules.json"


def test_base_skeleton_matches_golden() -> None:
    # Dogfoods the golden-file harness against the real committed fixture (nft -c where available).
    assert_golden(Ruleset(), "base_skeleton")


def test_output_is_json_serializable() -> None:
    # The generator feeds python3-nftables, which consumes JSON — it must round-trip.
    dumped = json.dumps(generate(Ruleset()))
    assert json.loads(dumped) == generate(Ruleset())


def _commands(kind: str) -> list[dict[str, Any]]:
    return [c["add"][kind] for c in generate(Ruleset())["nftables"] if kind in c["add"]]


def test_single_inet_filter_table() -> None:
    tables = _commands("table")
    assert tables == [{"family": "inet", "name": "filter"}]


def test_base_chains_are_fail_closed() -> None:
    chains = {c["name"]: c for c in _commands("chain")}
    assert set(chains) == {"input", "forward", "output"}
    assert chains["input"]["policy"] == "drop"
    assert chains["forward"]["policy"] == "drop"
    assert chains["output"]["policy"] == "accept"
    for chain in chains.values():
        assert (chain["type"], chain["hook"], chain["prio"]) == ("filter", chain["name"], 0)


def test_stateful_and_loopback_base_rules_present() -> None:
    rules = _commands("rule")
    exprs = [r["expr"] for r in rules]
    stateful = {
        "match": {
            "op": "in",
            "left": {"ct": {"key": "state"}},
            "right": {"set": ["established", "related"]},
        }
    }
    loopback = {
        "match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}
    }
    # established/related accept on both input and forward; loopback accept on input.
    input_rules = [r["expr"] for r in rules if r["chain"] == "input"]
    forward_rules = [r["expr"] for r in rules if r["chain"] == "forward"]
    assert [stateful, {"accept": None}] in input_rules
    assert [loopback, {"accept": None}] in input_rules
    assert [stateful, {"accept": None}] in forward_rules
    assert exprs  # non-empty


# ---- inter-zone default-policy rules (ADR-0006) -----------------------------------------

_FW = Zone(name="fw", is_firewall=True)


def _zone(name: str, *ifaces: str) -> Zone:
    members = tuple(ZoneMember(interface=i, family=Family.BOTH) for i in ifaces)
    return Zone(name=name, members=members)


def _rules(ruleset: Ruleset) -> list[dict[str, Any]]:
    return [c["add"]["rule"] for c in generate(ruleset)["nftables"] if "rule" in c["add"]]


def _iif(value: Any) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": value}}


def _oif(value: Any) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": value}}


def test_no_policies_leaves_base_skeleton_unchanged() -> None:
    assert generate(Ruleset(zones=(_FW, _zone("loc", "eth1")))) == generate(Ruleset())


def test_inter_zone_policy_emits_forward_rule_matching_both_interfaces() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1"), _zone("net", "eth0")),
        policies=(Policy(source="loc", dest="net", action="ACCEPT"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"] == [_iif("eth1"), _oif("eth0"), {"accept": None}]


def test_firewall_source_targets_output_chain_by_oifname() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="fw", dest="net", action="ACCEPT"),),
    )
    output = [r for r in _rules(rs) if r["chain"] == "output"]
    assert output[-1]["expr"] == [_oif("eth0"), {"accept": None}]


def test_firewall_dest_targets_input_chain_by_iifname() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1")),
        policies=(Policy(source="loc", dest="fw", action="DROP"),),
    )
    input_rules = [r for r in _rules(rs) if r["chain"] == "input"]
    assert input_rules[-1]["expr"] == [_iif("eth1"), {"drop": None}]


def test_all_source_omits_iifname() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="all", dest="net", action="DROP"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"] == [_oif("eth0"), {"drop": None}]


def test_all_dest_omits_oifname() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="net", dest="all", action="DROP"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"] == [_iif("eth0"), {"drop": None}]


def test_all_all_policy_is_a_bare_final_rule() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(
            Policy(source="net", dest="all", action="DROP"),
            Policy(source="all", dest="all", action="REJECT"),
        ),
    )
    rules = _rules(rs)
    assert rules[-1]["chain"] == "forward"
    assert rules[-1]["expr"] == [{"reject": None}]


@pytest.mark.parametrize(
    "action, verdict", [("ACCEPT", "accept"), ("DROP", "drop"), ("REJECT", "reject")]
)
def test_all_all_is_forward_only_and_never_opens_the_firewall(action: str, verdict: str) -> None:
    # ADR-0006 (intentional, #118): `all all` is the inter-zone forward catch-all only — it seeds
    # no input/output rule, so even `all all ACCEPT` does not open the firewall host (input stays
    # drop, output stays accept via the ADR-0005 base policies). Lock that for every verdict.
    zones = (_FW, _zone("net", "eth0"))
    base = _rules(Ruleset(zones=zones))
    added = _rules(
        Ruleset(zones=zones, policies=(Policy(source="all", dest="all", action=action),))
    )[len(base) :]
    assert [(r["chain"], r["expr"]) for r in added] == [("forward", [{verdict: None}])]


def test_log_level_emits_log_statement_before_verdict() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="net", dest="all", action="DROP", log_level="info"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"] == [_iif("eth0"), {"log": {"level": "info"}}, {"drop": None}]


def test_multiple_zone_interfaces_use_anonymous_set() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1", "eth2"), _zone("net", "eth0")),
        policies=(Policy(source="loc", dest="net", action="ACCEPT"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"][0] == _iif({"set": ["eth1", "eth2"]})


def test_specific_policies_ordered_before_all_catch_alls() -> None:
    # Input order is deliberately reversed from the required emit order.
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1"), _zone("net", "eth0")),
        policies=(
            Policy(source="all", dest="all", action="REJECT"),
            Policy(source="net", dest="all", action="DROP"),
            Policy(source="loc", dest="net", action="ACCEPT"),
        ),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    # The three policy rules are the last three forward rules, in specificity order.
    assert [r["expr"][-1] for r in forward[-3:]] == [
        {"accept": None},
        {"drop": None},
        {"reject": None},
    ]


def test_policy_zone_without_interfaces_fails_fast() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc"), _zone("net", "eth0")),
        policies=(Policy(source="loc", dest="net", action="ACCEPT"),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "loc" in str(exc.value)


def test_policy_default_rules_match_golden() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1"), _zone("net", "eth0")),
        policies=(
            Policy(source="loc", dest="net", action="ACCEPT"),
            Policy(source="fw", dest="net", action="ACCEPT"),
            Policy(source="net", dest="all", action="DROP", log_level="info"),
            Policy(source="all", dest="all", action="REJECT", log_level="info"),
        ),
    )
    assert generate(rs) == json.loads(POLICY_GOLDEN.read_text())


# ---- per-connection feature rules (ADR-0007) --------------------------------------------

def _port(field: str, proto: str, value: Any) -> dict[str, Any]:
    left = {"payload": {"protocol": proto, "field": field}}
    return {"match": {"op": "==", "left": left, "right": value}}


def _dport(proto: str, value: Any) -> dict[str, Any]:
    return _port("dport", proto, value)


def _sport(proto: str, value: Any) -> dict[str, Any]:
    return _port("sport", proto, value)


def _l4proto(value: str) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": value}}


def _added_rules(rs: Ruleset, zones: tuple[Zone, ...]) -> list[dict[str, Any]]:
    """The rules `rs` adds beyond the base skeleton for the same zones."""
    base = _rules(Ruleset(zones=zones))
    return _rules(rs)[len(base) :]


@pytest.mark.parametrize(
    "action, verdict", [("ACCEPT", "accept"), ("DROP", "drop"), ("REJECT", "reject")]
)
def test_rule_action_maps_to_verdict(action: str, verdict: str) -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(zones=zones, rules=(Rule(action=action, source="loc", dest="net"),))
    added = _added_rules(rs, zones)
    assert len(added) == 1
    assert added[0]["chain"] == "forward"
    assert added[0]["expr"] == [_iif("eth1"), _oif("eth0"), {verdict: None}]


def test_rule_tcp_single_dest_port() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22"),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"] == [_iif("eth1"), _oif("eth0"), _dport("tcp", 22), {"accept": None}]


def test_rule_udp_comma_list_dest_port_is_anonymous_set() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="udp", dport="53,853"),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"][2] == _dport("udp", {"set": [53, 853]})


def test_rule_dest_port_range() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="1024:2048"),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"][2] == _dport("tcp", {"range": [1024, 2048]})


def test_rule_source_port_uses_sport_field() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", sport="1024:65535"),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"][2] == _sport("tcp", {"range": [1024, 65535]})


def test_rule_both_ports_dest_before_source() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(
            Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="80", sport="1024"),
        ),
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _dport("tcp", 80),
        _sport("tcp", 1024),
        {"accept": None},
    ]


def test_rule_proto_only_matches_l4proto() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones, rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="udp"),)
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"] == [_iif("eth1"), _oif("eth0"), _l4proto("udp"), {"accept": None}]


def test_rule_to_firewall_lands_in_input_chain() -> None:
    zones = (_FW, _zone("loc", "eth1"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="fw", proto="tcp", dport="22"),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["chain"] == "input"
    assert added[0]["expr"] == [_iif("eth1"), _dport("tcp", 22), {"accept": None}]


def test_rule_from_firewall_lands_in_output_chain() -> None:
    zones = (_FW, _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="fw", dest="net", proto="tcp", dport="53"),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["chain"] == "output"
    assert added[0]["expr"] == [_oif("eth0"), _dport("tcp", 53), {"accept": None}]


def test_feature_rule_precedes_policy_default_in_same_chain() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22"),),
        policies=(Policy(source="loc", dest="net", action="DROP"),),
    )
    added = _added_rules(rs, zones)
    # The explicit ACCEPT rule is emitted before the zone-pair DROP default, so it wins.
    assert added[0]["expr"][-1] == {"accept": None}
    assert added[1]["expr"][-1] == {"drop": None}


def test_rules_preserve_input_order() -> None:
    zones = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(
            Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22"),
            Rule(action="DROP", source="loc", dest="net", proto="tcp", dport="23"),
        ),
    )
    added = _added_rules(rs, zones)
    assert [r["expr"][2] for r in added] == [_dport("tcp", 22), _dport("tcp", 23)]


def test_rule_all_source_omits_iifname() -> None:
    zones = (_FW, _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones, rules=(Rule(action="DROP", source="all", dest="net", proto="tcp", dport="22"),)
    )
    added = _added_rules(rs, zones)
    assert added[0]["expr"] == [_oif("eth0"), _dport("tcp", 22), {"drop": None}]


def test_rule_port_without_proto_fails_fast() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1"), _zone("net", "eth0")),
        rules=(Rule(action="ACCEPT", source="loc", dest="net", dport="22"),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "proto" in str(exc.value).lower()


def test_rule_zone_without_interfaces_fails_fast() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc"), _zone("net", "eth0")),
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22"),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "loc" in str(exc.value)


def test_rules_match_golden() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("loc", "eth1"), _zone("net", "eth0")),
        rules=(
            Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="80,443"),
            Rule(action="ACCEPT", source="loc", dest="fw", proto="tcp", dport="22"),
            Rule(action="REJECT", source="net", dest="loc", proto="udp", dport="1024:2048"),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    assert_golden(rs, "rule_verdicts_ports")


# ---- zone:host source/dest narrowing (task #123, ADR-0007) ------------------------------

_LN = (_FW, _zone("loc", "eth1"), _zone("net", "eth0"))


def _addr(field: str, proto: str, value: Any) -> dict[str, Any]:
    left = {"payload": {"protocol": proto, "field": field}}
    return {"match": {"op": "==", "left": left, "right": value}}


def test_ipv4_source_host_adds_ip_saddr_after_interfaces() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc:10.0.0.5", dest="net", family=Family.IPV4),),
    )
    added = _added_rules(rs, _LN)
    assert added[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _addr("saddr", "ip", "10.0.0.5"),
        {"accept": None},
    ]


def test_ipv4_dest_host_adds_ip_daddr() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc", dest="net:10.0.0.9", family=Family.IPV4),),
    )
    assert _addr("daddr", "ip", "10.0.0.9") in _added_rules(rs, _LN)[0]["expr"]


def test_both_hosts_saddr_before_daddr() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc:10.0.0.5", dest="net:10.0.0.9", family=Family.IPV4
            ),
        ),
    )
    assert _added_rules(rs, _LN)[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _addr("saddr", "ip", "10.0.0.5"),
        _addr("daddr", "ip", "10.0.0.9"),
        {"accept": None},
    ]


def test_ipv6_host_uses_ip6_payload() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc:2001:db8::1", dest="net", family=Family.IPV6),),
    )
    assert _addr("saddr", "ip6", "2001:db8::1") in _added_rules(rs, _LN)[0]["expr"]


def test_ipv4_cidr_host_uses_prefix() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc:10.36.36.0/24", dest="net", family=Family.IPV4),),
    )
    want = _addr("saddr", "ip", {"prefix": {"addr": "10.36.36.0", "len": 24}})
    assert want in _added_rules(rs, _LN)[0]["expr"]


def test_ipv6_cidr_host_uses_ip6_prefix() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc:2001:db8::/64", dest="net", family=Family.IPV6),),
    )
    want = _addr("saddr", "ip6", {"prefix": {"addr": "2001:db8::", "len": 64}})
    assert want in _added_rules(rs, _LN)[0]["expr"]


def test_firewall_source_host_targets_output_with_saddr() -> None:
    zones = (_FW, _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="fw:10.0.0.1", dest="net", family=Family.IPV4),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["chain"] == "output"
    assert added[0]["expr"] == [_oif("eth0"), _addr("saddr", "ip", "10.0.0.1"), {"accept": None}]


def test_firewall_dest_host_targets_input_with_daddr() -> None:
    zones = (_FW, _zone("loc", "eth1"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="fw:10.0.0.1", family=Family.IPV4),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["chain"] == "input"
    assert added[0]["expr"] == [_iif("eth1"), _addr("daddr", "ip", "10.0.0.1"), {"accept": None}]


def test_host_narrowing_precedes_l4_matches() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT",
                source="loc:10.0.0.5",
                dest="net",
                proto="tcp",
                dport="22",
                family=Family.IPV4,
            ),
        ),
    )
    assert _added_rules(rs, _LN)[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _addr("saddr", "ip", "10.0.0.5"),
        _dport("tcp", 22),
        {"accept": None},
    ]


def test_zone_host_narrowing_matches_golden() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT",
                source="loc:10.36.36.0/24",
                dest="net",
                proto="tcp",
                dport="22",
                family=Family.IPV4,
            ),
            Rule(
                action="ACCEPT",
                source="net",
                dest="fw:2001:db8::1",
                proto="tcp",
                dport="443",
                family=Family.IPV6,
            ),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    assert_golden(rs, "rule_zone_host_narrowing")


# ---- ?SECTION connection-state gating & ordering (task #124, ADR-0007) ------------------


def _ct(state: str) -> dict[str, Any]:
    return {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": state}}


def _sec(section: str | None, **kw: Any) -> Rule:
    return Rule(action="ACCEPT", source="loc", dest="net", section=section, **kw)


def test_established_section_gates_on_ct_state_established() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec("ESTABLISHED"),))
    assert _added_rules(rs, _LN)[0]["expr"] == [
        _iif("eth1"), _oif("eth0"), _ct("established"), {"accept": None}
    ]


def test_related_section_gates_on_ct_state_related() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec("RELATED"),))
    assert _ct("related") in _added_rules(rs, _LN)[0]["expr"]


def test_invalid_section_gates_on_ct_state_invalid() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec("INVALID"),))
    assert _ct("invalid") in _added_rules(rs, _LN)[0]["expr"]


def test_new_section_is_ungated() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec("NEW"),))
    assert _added_rules(rs, _LN)[0]["expr"] == [_iif("eth1"), _oif("eth0"), {"accept": None}]


def test_unsectioned_defaults_to_new_and_is_ungated() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec(None),))
    assert _added_rules(rs, _LN)[0]["expr"] == [_iif("eth1"), _oif("eth0"), {"accept": None}]


def test_section_name_is_case_insensitive() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec("established"),))
    assert _ct("established") in _added_rules(rs, _LN)[0]["expr"]


def test_sections_ordered_established_related_invalid_new() -> None:
    # Input order is deliberately reversed from the required emit order.
    rs = Ruleset(
        zones=_LN,
        rules=(_sec("NEW"), _sec("INVALID"), _sec("RELATED"), _sec("ESTABLISHED")),
    )
    added = _added_rules(rs, _LN)
    gates = [next((e for e in r["expr"] if "ct" in str(e)), "new") for r in added]
    assert gates == [_ct("established"), _ct("related"), _ct("invalid"), "new"]


def test_stable_order_within_a_section() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22", section="NEW"),
            Rule(action="DROP", source="loc", dest="net", proto="tcp", dport="23", section="NEW"),
        ),
    )
    added = _added_rules(rs, _LN)
    assert [r["expr"][-1] for r in added] == [{"accept": None}, {"drop": None}]


def test_ct_state_sits_between_address_and_l4() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT",
                source="loc:10.0.0.5",
                dest="net",
                proto="tcp",
                dport="22",
                section="RELATED",
                family=Family.IPV4,
            ),
        ),
    )
    assert _added_rules(rs, _LN)[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _addr("saddr", "ip", "10.0.0.5"),
        _ct("related"),
        _dport("tcp", 22),
        {"accept": None},
    ]


def test_unknown_section_fails_fast() -> None:
    rs = Ruleset(zones=_LN, rules=(_sec("BOGUS"),))
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "SECTION" in str(exc.value) or "section" in str(exc.value)


def test_sectioned_rules_match_golden() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="22", section="NEW"),
            Rule(action="DROP", source="net", dest="loc", section="INVALID"),
            Rule(action="ACCEPT", source="loc", dest="net", section="ESTABLISHED"),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    assert_golden(rs, "rule_sections")


# ---- ICMP rules, family-correct icmp/ipv6-icmp (task #122, ADR-0007) --------------------


def _icmp_type(proto: str, value: Any) -> dict[str, Any]:
    left = {"payload": {"protocol": proto, "field": "type"}}
    return {"match": {"op": "==", "left": left, "right": value}}


def test_ipv4_icmp_proto_only_matches_l4proto() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="icmp", family=Family.IPV4),),
    )
    added = _added_rules(rs, _LN)
    assert len(added) == 1
    assert added[0]["expr"] == [_iif("eth1"), _oif("eth0"), _l4proto("icmp"), {"accept": None}]


def test_ipv6_icmp_proto_only_matches_l4proto() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(action="ACCEPT", source="loc", dest="net", proto="ipv6-icmp", family=Family.IPV6),
        ),
    )
    assert _l4proto("ipv6-icmp") in _added_rules(rs, _LN)[0]["expr"]


def test_ipv4_icmp_type_uses_icmp_payload() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc", dest="net", proto="icmp",
                dport="echo-request", family=Family.IPV4,
            ),
        ),
    )
    assert _icmp_type("icmp", "echo-request") in _added_rules(rs, _LN)[0]["expr"]


def test_ipv6_icmp_type_uses_icmpv6_payload() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc", dest="net", proto="ipv6-icmp",
                dport="128", family=Family.IPV6,
            ),
        ),
    )
    assert _icmp_type("icmpv6", 128) in _added_rules(rs, _LN)[0]["expr"]


def test_both_family_icmp_splits_into_two_family_rules() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="icmp", family=Family.BOTH),),
    )
    added = _added_rules(rs, _LN)
    assert len(added) == 2
    assert _l4proto("icmp") in added[0]["expr"]
    assert _l4proto("ipv6-icmp") in added[1]["expr"]


def test_both_family_icmp_with_type_splits_both_payloads() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc", dest="net", proto="icmp",
                dport="8", family=Family.BOTH,
            ),
        ),
    )
    added = _added_rules(rs, _LN)
    assert _icmp_type("icmp", 8) in added[0]["expr"]
    assert _icmp_type("icmpv6", 8) in added[1]["expr"]


def test_icmp_match_after_interfaces_before_verdict() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc", dest="net", proto="icmp",
                dport="echo-request", family=Family.IPV4,
            ),
        ),
    )
    assert _added_rules(rs, _LN)[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _icmp_type("icmp", "echo-request"),
        {"accept": None},
    ]


def test_icmp_with_source_port_fails_fast() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc", dest="net", proto="icmp",
                sport="1024", family=Family.IPV4,
            ),
        ),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "icmp" in str(exc.value).lower()


def test_icmp_rules_match_golden() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="net", dest="fw", proto="icmp",
                dport="echo-request", family=Family.IPV4,
            ),
            Rule(
                action="ACCEPT", source="net", dest="fw", proto="ipv6-icmp",
                dport="echo-request", family=Family.IPV6,
            ),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    assert_golden(rs, "rule_icmp")
