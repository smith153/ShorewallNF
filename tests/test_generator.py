import json
from pathlib import Path
from typing import Any

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.generator import generate, generate_stopped
from shorewallnf.ir import (
    ConntrackHelper,
    Family,
    HelperCapabilities,
    Nat,
    Policy,
    Rule,
    Ruleset,
    Settings,
    Zone,
    ZoneMember,
)
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
    # Default Settings: level from LOG_LEVEL (info), prefix from the LOGFORMAT template with
    # its %s slots filled by chain (forward) and disposition (the policy action, DROP).
    assert forward[-1]["expr"] == [
        _iif("eth0"),
        {"log": {"level": "info", "prefix": "Shorewall:forward:DROP:"}},
        {"drop": None},
    ]


def test_settings_drive_log_level_and_prefix() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="net", dest="all", action="DROP", log_level="info"),),
        settings=Settings(log_level="warning", logformat="MyFW:%s:%s:"),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"][-2] == {
        "log": {"level": "warning", "prefix": "MyFW:forward:DROP:"}
    }


def test_single_slot_logformat_fills_chain_only() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="net", dest="all", action="DROP", log_level="info"),),
        settings=Settings(logformat="fw-%s:"),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    assert forward[-1]["expr"][-2] == {"log": {"level": "info", "prefix": "fw-forward:"}}


def test_over_length_rendered_prefix_fails_fast() -> None:
    # Template is within the 127-char limit, but substituting the chain name renders past it —
    # the generator must validate the *rendered* prefix, not just the template.
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="net", dest="all", action="DROP", log_level="info"),),
        settings=Settings(logformat="L" * 124 + "%s:"),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "127" in str(exc.value) and "prefix" in str(exc.value)


def test_logformat_with_too_many_slots_fails_fast() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        policies=(Policy(source="net", dest="all", action="DROP", log_level="info"),),
        settings=Settings(logformat="a:%s:%s:%s:"),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "%s" in str(exc.value)


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
        rules=(Rule(action="ACCEPT", source="loc:192.0.2.5", dest="net", family=Family.IPV4),),
    )
    added = _added_rules(rs, _LN)
    assert added[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _addr("saddr", "ip", "192.0.2.5"),
        {"accept": None},
    ]


def test_ipv4_dest_host_adds_ip_daddr() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(Rule(action="ACCEPT", source="loc", dest="net:192.0.2.9", family=Family.IPV4),),
    )
    assert _addr("daddr", "ip", "192.0.2.9") in _added_rules(rs, _LN)[0]["expr"]


def test_both_hosts_saddr_before_daddr() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT", source="loc:192.0.2.5", dest="net:192.0.2.9", family=Family.IPV4
            ),
        ),
    )
    assert _added_rules(rs, _LN)[0]["expr"] == [
        _iif("eth1"),
        _oif("eth0"),
        _addr("saddr", "ip", "192.0.2.5"),
        _addr("daddr", "ip", "192.0.2.9"),
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
        rules=(
            Rule(action="ACCEPT", source="loc:198.51.100.0/24", dest="net", family=Family.IPV4),
        ),
    )
    want = _addr("saddr", "ip", {"prefix": {"addr": "198.51.100.0", "len": 24}})
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
        rules=(Rule(action="ACCEPT", source="fw:192.0.2.1", dest="net", family=Family.IPV4),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["chain"] == "output"
    assert added[0]["expr"] == [_oif("eth0"), _addr("saddr", "ip", "192.0.2.1"), {"accept": None}]


def test_firewall_dest_host_targets_input_with_daddr() -> None:
    zones = (_FW, _zone("loc", "eth1"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="fw:192.0.2.1", family=Family.IPV4),),
    )
    added = _added_rules(rs, zones)
    assert added[0]["chain"] == "input"
    assert added[0]["expr"] == [_iif("eth1"), _addr("daddr", "ip", "192.0.2.1"), {"accept": None}]


def test_host_narrowing_precedes_l4_matches() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT",
                source="loc:192.0.2.5",
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
        _addr("saddr", "ip", "192.0.2.5"),
        _dport("tcp", 22),
        {"accept": None},
    ]


def test_zone_host_narrowing_matches_golden() -> None:
    rs = Ruleset(
        zones=_LN,
        rules=(
            Rule(
                action="ACCEPT",
                source="loc:198.51.100.0/24",
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
                source="loc:192.0.2.5",
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
        _addr("saddr", "ip", "192.0.2.5"),
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


# ---- IPv4 DNAT: nat prerouting + forward accept (task #143, ADR-0008) --------------------


def _nat_cmds(kind: str, table: str, ruleset: Ruleset) -> list[dict[str, Any]]:
    """The `add` payloads of the given kind in the given table from `generate(ruleset)`.

    A `table` payload is keyed by `name` (it *is* the table); `chain`/`rule` payloads carry a
    `table` field.
    """
    out = []
    for cmd in generate(ruleset)["nftables"]:
        payload = cmd["add"].get(kind)
        if payload is None:
            continue
        owner = payload["name"] if kind == "table" else payload["table"]
        if owner == table:
            out.append(payload)
    return out


def _daddr(proto: str, value: Any) -> dict[str, Any]:
    left = {"payload": {"protocol": proto, "field": "daddr"}}
    return {"match": {"op": "==", "left": left, "right": value}}


# net(eth0) is the external source zone; loc(eth1) the internal zone the DNAT targets.
_NL = (_FW, _zone("net", "eth0"), _zone("loc", "eth1"))


def _dnat(host: str, port: Any | None = None) -> dict[str, Any]:
    target: dict[str, Any] = {"addr": host, "family": "ip"}
    if port is not None:
        target["port"] = port
    return {"dnat": target}


def test_no_nats_leaves_base_skeleton_unchanged() -> None:
    assert generate(Ruleset(zones=_NL, nats=())) == generate(Ruleset(zones=_NL))
    # ...and with no nats there is no inet nat table at all.
    assert _nat_cmds("table", "nat", Ruleset(zones=_NL)) == []


def test_dnat_emits_inet_nat_table_and_base_chains() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80", family=Family.IPV4),),
    )
    assert {"family": "inet", "name": "nat"} in _nat_cmds("table", "nat", rs)
    chains = {c["name"]: c for c in _nat_cmds("chain", "nat", rs)}
    assert set(chains) == {"prerouting", "postrouting"}
    assert (chains["prerouting"]["type"], chains["prerouting"]["hook"]) == ("nat", "prerouting")
    assert chains["prerouting"]["prio"] == -100
    assert (chains["postrouting"]["type"], chains["postrouting"]["hook"]) == ("nat", "postrouting")
    assert chains["postrouting"]["prio"] == 100
    for chain in chains.values():
        assert chain["policy"] == "accept"


def test_dnat_prerouting_rule_matches_iif_proto_dport_and_dnat_target() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80", family=Family.IPV4),),
    )
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    assert len(prerouting) == 1
    assert prerouting[0]["expr"] == [_iif("eth0"), _dport("tcp", 80), _dnat("192.0.2.10")]


def test_dnat_emits_forward_accept_to_internal_host() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80", family=Family.IPV4),),
    )
    added = _added_rules(rs, _NL)
    forward = [r for r in added if r["chain"] == "forward"]
    assert len(forward) == 1
    assert forward[0]["expr"] == [
        _iif("eth0"),
        _oif("eth1"),
        _daddr("ip", "192.0.2.10"),
        _dport("tcp", 80),
        {"accept": None},
    ]


def test_dnat_comma_list_dest_port_is_anonymous_set() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80,443", family=Family.IPV4),),
    )
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    assert prerouting[0]["expr"][1] == _dport("tcp", {"set": [80, 443]})


def test_dnat_dest_port_range() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="udp",
                  dport="49160:49300", family=Family.IPV4),),
    )
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    assert prerouting[0]["expr"][1] == _dport("udp", {"range": [49160, 49300]})


def test_dnat_target_port_remap_rewrites_dnat_and_forward_port() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10:8080", proto="tcp",
                  dport="80", family=Family.IPV4),),
    )
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    # prerouting matches the EXTERNAL port; the dnat target carries the REMAPPED port.
    assert prerouting[0]["expr"] == [_iif("eth0"), _dport("tcp", 80), _dnat("192.0.2.10", 8080)]
    forward = [r for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    # the forward accept matches the post-DNAT (remapped) port on the internal host.
    assert forward[0]["expr"] == [
        _iif("eth0"),
        _oif("eth1"),
        _daddr("ip", "192.0.2.10"),
        _dport("tcp", 8080),
        {"accept": None},
    ]


def test_dnat_without_remap_forward_matches_external_port() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="22", family=Family.IPV4),),
    )
    forward = [r for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    assert _dport("tcp", 22) in forward[0]["expr"]


def test_dnat_forward_accept_precedes_policy_default_in_forward_chain() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80", family=Family.IPV4),),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    # the DNAT accept is reached before the `all all DROP` fall-through.
    assert forward[-2]["expr"][-1] == {"accept": None}
    assert forward[-1]["expr"] == [{"drop": None}]


def test_dnat_all_source_omits_iifname() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="all", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80", family=Family.IPV4),),
    )
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    assert prerouting[0]["expr"] == [_dport("tcp", 80), _dnat("192.0.2.10")]


def test_dnat_port_without_proto_fails_fast() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", dport="80"),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "proto" in str(exc.value).lower()


def test_dnat_zone_without_interfaces_fails_fast() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net"), _zone("loc", "eth1")),
        nats=(Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                  dport="80", family=Family.IPV4),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "net" in str(exc.value)


def test_dnat_matches_golden() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(
            Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                dport="80,443", family=Family.IPV4),
            Nat(action="DNAT", source="net", dest="loc", to="192.0.2.20:8022", proto="tcp",
                dport="22", family=Family.IPV4),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    assert_golden(rs, "dnat_prerouting_forward")


# ---- IPv6 DNAT: direct forward accept, no NAT (task #144, ADR-0002) ----------------------
#
# IPv6 does no NAT (ADR-0002): a DNAT whose target is a global v6 address compiles to a plain
# forward ACCEPT to that address — no nat table / prerouting. net(eth0) → loc(eth1), as above.


def test_ipv6_dnat_emits_no_nat_table_or_prerouting() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                  dport="443", family=Family.IPV6),),
    )
    assert _nat_cmds("table", "nat", rs) == []
    assert _nat_cmds("chain", "nat", rs) == []
    assert _nat_cmds("rule", "nat", rs) == []


def test_ipv6_dnat_emits_direct_forward_accept_to_v6_address() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                  dport="443", family=Family.IPV6),),
    )
    forward = [r for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    assert len(forward) == 1
    assert forward[0]["expr"] == [
        _iif("eth0"),
        _oif("eth1"),
        _daddr("ip6", "2001:db8::5"),
        _dport("tcp", 443),
        {"accept": None},
    ]


def test_ipv6_dnat_comma_list_dest_port_is_anonymous_set() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                  dport="80,443", family=Family.IPV6),),
    )
    forward = [r for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    assert _dport("tcp", {"set": [80, 443]}) in forward[0]["expr"]


def test_ipv6_dnat_proto_only_matches_l4proto() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                  family=Family.IPV6),),
    )
    forward = [r for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    assert forward[0]["expr"] == [
        _iif("eth0"),
        _oif("eth1"),
        _daddr("ip6", "2001:db8::5"),
        _l4proto("tcp"),
        {"accept": None},
    ]


def test_ipv6_dnat_forward_accept_precedes_policy_default() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                  dport="443", family=Family.IPV6),),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    forward = [r for r in _rules(rs) if r["chain"] == "forward"]
    # the v6 accept is reached before the `all all DROP` fall-through.
    assert forward[-2]["expr"][-1] == {"accept": None}
    assert forward[-1]["expr"] == [{"drop": None}]


def test_ipv6_dnat_all_source_omits_iifname() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="all", dest="loc", to="2001:db8::5", proto="tcp",
                  dport="443", family=Family.IPV6),),
    )
    forward = [r for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    assert forward[0]["expr"] == [
        _oif("eth1"),
        _daddr("ip6", "2001:db8::5"),
        _dport("tcp", 443),
        {"accept": None},
    ]


def test_ipv6_dnat_port_without_proto_fails_fast() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", dport="443",
                  family=Family.IPV6),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "proto" in str(exc.value).lower()


def test_dual_stack_dnat_yields_v4_nat_and_v6_direct_accept() -> None:
    # One service-exposure intent, dual-stack: v4 DNAT (nat prerouting + forward) AND v6
    # direct-accept (no NAT), in the one inet ruleset.
    rs = Ruleset(
        zones=_NL,
        nats=(
            Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                dport="443", family=Family.IPV4),
            Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                dport="443", family=Family.IPV6),
        ),
    )
    # v4 goes through the nat table (a prerouting dnat); v6 does not.
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    assert len(prerouting) == 1
    # both forward accepts coexist in the one inet filter forward chain — ip4 and ip6 daddr.
    forward_exprs = [r["expr"] for r in _added_rules(rs, _NL) if r["chain"] == "forward"]
    assert any(_daddr("ip", "192.0.2.10") in expr for expr in forward_exprs)
    assert any(_daddr("ip6", "2001:db8::5") in expr for expr in forward_exprs)


def test_ipv6_dnat_matches_golden() -> None:
    rs = Ruleset(
        zones=_NL,
        nats=(
            Nat(action="DNAT", source="net", dest="loc", to="2001:db8::5", proto="tcp",
                dport="80,443", family=Family.IPV6),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    assert_golden(rs, "dnat_ipv6_direct_accept")


# ---- IPv4 SNAT/MASQUERADE: nat postrouting source NAT (task #157, ADR-0009) --------------
#
# Source NAT is IPv4-only (ADR-0002). A MASQUERADE/SNAT `Nat` carries literal `source_nets`
# (a comma-CIDR list) and an `out_interface`, not zones: the rule matches `oifname <out>` then
# `ip saddr <source_nets>` (ADR-0007 order), then the source-NAT target. Unlike DNAT there is NO
# forward accept — source NAT opens no new forward path.


def _saddr(value: Any) -> dict[str, Any]:
    left = {"payload": {"protocol": "ip", "field": "saddr"}}
    return {"match": {"op": "==", "left": left, "right": value}}


def _prefix(addr: str, length: int) -> dict[str, Any]:
    return {"prefix": {"addr": addr, "len": length}}


def _postrouting(rs: Ruleset) -> list[dict[str, Any]]:
    return [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "postrouting"]


def test_masquerade_only_emits_nat_table_and_postrouting_chain() -> None:
    # A SNAT-only ruleset still needs the nat table (the postrouting chain hosts the rule).
    rs = Ruleset(nats=(Nat(action="MASQUERADE", source_nets="192.0.2.0/24",
                           out_interface="eth0"),))
    assert {"family": "inet", "name": "nat"} in _nat_cmds("table", "nat", rs)
    chains = {c["name"]: c for c in _nat_cmds("chain", "nat", rs)}
    assert set(chains) == {"prerouting", "postrouting"}


def test_masquerade_postrouting_rule_matches_oif_saddr_then_masquerade() -> None:
    rs = Ruleset(nats=(Nat(action="MASQUERADE", source_nets="192.0.2.0/24",
                           out_interface="eth0"),))
    pr = _postrouting(rs)
    assert len(pr) == 1
    assert pr[0]["expr"] == [
        _oif("eth0"),
        _saddr(_prefix("192.0.2.0", 24)),
        {"masquerade": None},
    ]


def test_explicit_snat_emits_snat_to_addr() -> None:
    rs = Ruleset(nats=(Nat(action="SNAT", source_nets="192.0.2.0/24", out_interface="eth0",
                           snat_to="203.0.113.5"),))
    pr = _postrouting(rs)
    assert pr[0]["expr"] == [
        _oif("eth0"),
        _saddr(_prefix("192.0.2.0", 24)),
        {"snat": {"addr": "203.0.113.5", "family": "ip"}},
    ]


def test_snat_multi_cidr_source_list_is_anonymous_set() -> None:
    rs = Ruleset(nats=(Nat(action="MASQUERADE",
                           source_nets="192.0.2.0/24,198.51.100.0/24", out_interface="eth0"),))
    pr = _postrouting(rs)
    assert pr[0]["expr"][1] == _saddr(
        {"set": [_prefix("192.0.2.0", 24), _prefix("198.51.100.0", 24)]}
    )


def test_snat_bare_source_address_is_scalar() -> None:
    # A source without a prefix length passes through as a scalar (no /len → no `prefix`).
    rs = Ruleset(nats=(Nat(action="MASQUERADE", source_nets="192.0.2.5",
                           out_interface="eth0"),))
    assert _postrouting(rs)[0]["expr"][1] == _saddr("192.0.2.5")


def test_snat_adds_no_filter_forward_rule() -> None:
    # Source NAT opens no new forward path (contrast DNAT's forward accept).
    rs = Ruleset(nats=(Nat(action="MASQUERADE", source_nets="192.0.2.0/24",
                           out_interface="eth0"),))
    snat_forward = [r for r in _rules(rs) if r["table"] == "filter" and r["chain"] == "forward"]
    base_forward = [
        r for r in _rules(Ruleset()) if r["table"] == "filter" and r["chain"] == "forward"
    ]
    assert snat_forward == base_forward


def test_dnat_and_snat_coexist_in_one_ruleset() -> None:
    # The nat dispatch routes DNAT → prerouting and SNAT/MASQUERADE → postrouting, untouched.
    rs = Ruleset(
        zones=_NL,
        nats=(
            Nat(action="DNAT", source="net", dest="loc", to="192.0.2.10", proto="tcp",
                dport="80", family=Family.IPV4),
            Nat(action="MASQUERADE", source_nets="192.0.2.0/24", out_interface="eth0"),
        ),
    )
    prerouting = [r for r in _nat_cmds("rule", "nat", rs) if r["chain"] == "prerouting"]
    assert len(prerouting) == 1
    assert prerouting[0]["expr"] == [_iif("eth0"), _dport("tcp", 80), _dnat("192.0.2.10")]
    assert _postrouting(rs)[0]["expr"] == [
        _oif("eth0"),
        _saddr(_prefix("192.0.2.0", 24)),
        {"masquerade": None},
    ]


def test_snat_masquerade_matches_golden() -> None:
    rs = Ruleset(
        nats=(
            Nat(action="MASQUERADE", source_nets="192.0.2.0/24,198.51.100.0/24",
                out_interface="eth0"),
            Nat(action="SNAT", source_nets="203.0.113.0/24", out_interface="eth1",
                snat_to="198.51.100.1"),
        ),
    )
    assert_golden(rs, "snat_postrouting")


def test_snat_without_out_interface_fails_fast() -> None:
    # Fail closed (ADR-0004, ADR-0009 §7): a source-NAT entry with no egress interface has no
    # `oifname` to match, so it must refuse rather than emit a broken postrouting rule.
    rs = Ruleset(nats=(Nat(action="MASQUERADE", source_nets="192.0.2.0/24"),))
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "egress interface" in str(exc.value).lower()


def test_snat_without_source_nets_fails_fast() -> None:
    # Fail closed (ADR-0004, ADR-0009 §7): a source-NAT entry with no source network has no
    # `ip saddr` family guard, so it must refuse rather than masquerade every source.
    rs = Ruleset(nats=(Nat(action="MASQUERADE", out_interface="eth0"),))
    with pytest.raises(ConfigError) as exc:
        generate(rs)
    assert "source network" in str(exc.value).lower()


# ---- stopped safe-state ruleset (task #211, ADR-0021) ------------------------------------
#
# `generate_stopped` renders the fail-safe ruleset installed while the firewall is stopped
# (#212 installs it). Default-drop base chains keep everything closed, but the no-lockout
# baseline (loopback + established/related) plus the parsed admin `stopped_rules` are always
# admitted so an operator is never orphaned. It consumes ONLY `stopped_rules` — never the
# running `rules`/`policies`/`nats`.


def _stopped_rules(rs: Ruleset) -> list[dict[str, Any]]:
    return [c["add"]["rule"] for c in generate_stopped(rs)["nftables"] if "rule" in c["add"]]


def _stopped_chains(rs: Ruleset) -> dict[str, dict[str, Any]]:
    return {
        c["add"]["chain"]["name"]: c["add"]["chain"]
        for c in generate_stopped(rs)["nftables"]
        if "chain" in c["add"]
    }


def test_stopped_state_is_single_inet_filter_table() -> None:
    tables = [
        c["add"]["table"] for c in generate_stopped(Ruleset())["nftables"] if "table" in c["add"]
    ]
    assert tables == [{"family": "inet", "name": "filter"}]


def test_stopped_base_chains_are_default_drop() -> None:
    chains = _stopped_chains(Ruleset())
    assert set(chains) == {"input", "forward", "output"}
    assert chains["input"]["policy"] == "drop"
    assert chains["forward"]["policy"] == "drop"
    assert chains["output"]["policy"] == "accept"


def test_stopped_state_admits_loopback_and_stateful_baseline() -> None:
    # No-lockout baseline: even with ZERO admin rules the stopped state still admits loopback
    # and established/related return traffic — no silent lockout, no all-ports-open.
    rules = _stopped_rules(Ruleset())
    stateful = {
        "match": {
            "op": "in",
            "left": {"ct": {"key": "state"}},
            "right": {"set": ["established", "related"]},
        }
    }
    loopback = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}
    input_rules = [r["expr"] for r in rules if r["chain"] == "input"]
    forward_rules = [r["expr"] for r in rules if r["chain"] == "forward"]
    assert [stateful, {"accept": None}] in input_rules
    assert [loopback, {"accept": None}] in input_rules
    assert [stateful, {"accept": None}] in forward_rules


def test_stopped_state_with_zero_admin_rules_is_exactly_the_baseline() -> None:
    # Zero admin rules → the emitted ruleset is precisely the default-drop skeleton + baseline
    # accepts. Nothing more is opened (no all-ports-open), nothing less (no total lockout).
    rules = _stopped_rules(Ruleset())
    assert [(r["chain"], r["expr"][-1]) for r in rules] == [
        ("input", {"accept": None}),
        ("input", {"accept": None}),
        ("forward", {"accept": None}),
    ]


def test_stopped_admin_rule_to_firewall_lands_in_input_chain() -> None:
    # Admin SSH from a management host is translated exactly as the main rules generator would,
    # landing in the input chain past the baseline accepts.
    zones = (_FW, _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        stopped_rules=(
            Rule(
                action="ACCEPT", source="net:198.51.100.10", dest="fw",
                proto="tcp", dport="22", family=Family.IPV4,
            ),
        ),
    )
    admin = [r for r in _stopped_rules(rs) if r["chain"] == "input"][-1]
    assert admin["expr"] == [
        _iif("eth0"),
        _addr("saddr", "ip", "198.51.100.10"),
        _dport("tcp", 22),
        {"accept": None},
    ]


def test_stopped_admin_rules_are_family_correct() -> None:
    # A v4 and a v6 admin rule each carry their own family guard (ip vs ip6 saddr) in the one
    # inet table — same dual-stack handling as the running rules generator (ADR-0002).
    zones = (_FW, _zone("net", "eth0"))
    rs = Ruleset(
        zones=zones,
        stopped_rules=(
            Rule(action="ACCEPT", source="net:198.51.100.10", dest="fw",
                 proto="tcp", dport="22", family=Family.IPV4),
            Rule(action="ACCEPT", source="net:2001:db8::10", dest="fw",
                 proto="tcp", dport="22", family=Family.IPV6),
        ),
    )
    exprs = [r["expr"] for r in _stopped_rules(rs) if r["chain"] == "input"]
    assert any(_addr("saddr", "ip", "198.51.100.10") in e for e in exprs)
    assert any(_addr("saddr", "ip6", "2001:db8::10") in e for e in exprs)


def test_stopped_state_ignores_running_rules_policies_and_nats() -> None:
    # The stopped state is built ONLY from stopped_rules: the running config's rules, policies,
    # and NATs are invisible to it (that is what makes it a self-contained safe state).
    zones = (_FW, _zone("net", "eth0"), _zone("loc", "eth1"))
    rs = Ruleset(
        zones=zones,
        rules=(Rule(action="ACCEPT", source="loc", dest="net", proto="tcp", dport="80"),),
        policies=(Policy(source="all", dest="all", action="ACCEPT"),),
        nats=(Nat(action="MASQUERADE", source_nets="192.0.2.0/24", out_interface="eth0"),),
    )
    assert generate_stopped(rs) == generate_stopped(Ruleset(zones=zones))


def test_stopped_admin_rule_zone_without_interfaces_fails_fast() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net")),
        stopped_rules=(
            Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22"),
        ),
    )
    with pytest.raises(ConfigError) as exc:
        generate_stopped(rs)
    assert "net" in str(exc.value)


def test_stopped_state_matches_golden() -> None:
    rs = Ruleset(
        zones=(_FW, _zone("net", "eth0")),
        stopped_rules=(
            Rule(action="ACCEPT", source="net:198.51.100.10", dest="fw",
                 proto="tcp", dport="22", family=Family.IPV4),
            Rule(action="ACCEPT", source="net:2001:db8::10", dest="fw",
                 proto="tcp", dport="22", family=Family.IPV6),
        ),
    )
    assert_golden(rs, "stopped_safe_state", generator=generate_stopped)


# ---- conntrack helper objects + assignment rules (task #221, ADR-0041) ------------------
#
# A ConntrackHelper IR entry (#219/ADR-0040) compiles to a per-table `ct helper` object plus a
# `ct helper set` assignment rule in the correct base chain, family-scoped (ADR-0002) and gated
# on the compile-time HelperCapabilities surface (AUTOHELPERS-equivalent). A v6-capable helper
# gets an `l3proto inet` object with an unguarded rule; a v4-only helper gets an `l3proto ip`
# object with a `meta nfproto ipv4`-scoped rule (no v6 path); an unavailable helper is skipped
# with a warning, never emitted. Object JSON per /usr/share/doc/nftables/examples/ct_helpers.nft.

# Every documented helper available — the "kernel provides them all" capability surface.
_ALL_HELPERS = HelperCapabilities(available=frozenset({"ftp", "tftp", "sip", "pptp"}))

# net(eth0) faces the firewall; loc(eth1) is the internal zone a forwarded helper flows toward.
_NFW = (_FW, _zone("net", "eth0"))
_NLC = (_FW, _zone("net", "eth0"), _zone("loc", "eth1"))


def _nfproto(fam: str) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": fam}}


def _cth_objects(rs: Ruleset, caps: HelperCapabilities = _ALL_HELPERS) -> list[dict[str, Any]]:
    return [
        c["add"]["ct helper"]
        for c in generate(rs, capabilities=caps)["nftables"]
        if "ct helper" in c["add"]
    ]


def _cth_rules(rs: Ruleset, caps: HelperCapabilities = _ALL_HELPERS) -> list[dict[str, Any]]:
    return [
        c["add"]["rule"] for c in generate(rs, capabilities=caps)["nftables"] if "rule" in c["add"]
    ]


def _added_helper_rules(rs: Ruleset, zones: tuple[Zone, ...]) -> list[dict[str, Any]]:
    """The assignment rules `rs` adds beyond the base skeleton (which has no helpers)."""
    base = _rules(Ruleset(zones=zones))
    return _cth_rules(rs)[len(base) :]


def _ftp(source: str = "net", dest: str = "fw", **kw: Any) -> ConntrackHelper:
    return ConntrackHelper(name="ftp", source=source, dest=dest, family=Family.BOTH, **kw)


def test_v6_capable_helper_emits_inet_object() -> None:
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(),))
    assert _cth_objects(rs) == [
        {
            "family": "inet",
            "table": "filter",
            "name": "ftp",
            "type": "ftp",
            "protocol": "tcp",
            "l3proto": "inet",
        }
    ]


def test_v6_capable_helper_assignment_rule_is_unguarded_in_input() -> None:
    # dest=fw → input chain; iifname matches the source zone; no meta nfproto guard (dual-stack).
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(),))
    added = _added_helper_rules(rs, _NFW)
    assert len(added) == 1
    assert added[0]["chain"] == "input"
    assert added[0]["expr"] == [_iif("eth0"), _dport("tcp", 21), {"ct helper": "ftp"}]


def test_helper_default_port_comes_from_the_registry() -> None:
    # No per-row proto/dport → the assignment matches the helper's canonical proto/default port.
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(),))
    assert _dport("tcp", 21) in _added_helper_rules(rs, _NFW)[0]["expr"]


def test_per_row_dport_narrows_the_match() -> None:
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(proto="tcp", dport="2121"),))
    expr = _added_helper_rules(rs, _NFW)[0]["expr"]
    assert _dport("tcp", 2121) in expr
    assert _dport("tcp", 21) not in expr


def test_helper_through_firewall_lands_in_forward_matching_both_interfaces() -> None:
    rs = Ruleset(zones=_NLC, conntrack_helpers=(_ftp(source="net", dest="loc"),))
    added = _added_helper_rules(rs, _NLC)
    assert added[0]["chain"] == "forward"
    assert added[0]["expr"] == [_iif("eth0"), _oif("eth1"), _dport("tcp", 21), {"ct helper": "ftp"}]


def test_v4_only_helper_object_is_l3proto_ip() -> None:
    rs = Ruleset(
        zones=_NFW,
        conntrack_helpers=(
            ConntrackHelper(name="pptp", source="net", dest="fw", family=Family.IPV4),
        ),
    )
    assert _cth_objects(rs) == [
        {
            "family": "inet",
            "table": "filter",
            "name": "pptp",
            "type": "pptp",
            "protocol": "tcp",
            "l3proto": "ip",
        }
    ]


def test_v4_only_helper_rule_is_v4_scoped_with_no_v6_path() -> None:
    rs = Ruleset(
        zones=_NFW,
        conntrack_helpers=(
            ConntrackHelper(name="pptp", source="net", dest="fw", family=Family.IPV4),
        ),
    )
    added = _added_helper_rules(rs, _NFW)
    assert len(added) == 1
    assert added[0]["expr"] == [
        _iif("eth0"),
        _nfproto("ipv4"),
        _dport("tcp", 1723),
        {"ct helper": "pptp"},
    ]
    # A v6-incapable helper emits no v6 path at all (ADR-0002).
    blob = json.dumps(added)
    assert "ip6" not in blob and "ipv6" not in blob


def test_dual_stack_and_v4_only_helpers_coexist() -> None:
    # One v6-capable + one v4-only helper in the one inet table: only the v4-only rule is guarded.
    rs = Ruleset(
        zones=_NLC,
        conntrack_helpers=(
            _ftp(source="net", dest="fw"),
            ConntrackHelper(name="pptp", source="net", dest="loc", family=Family.IPV4),
        ),
    )
    objects = {o["name"]: o for o in _cth_objects(rs)}
    assert objects["ftp"]["l3proto"] == "inet"
    assert objects["pptp"]["l3proto"] == "ip"
    added = _added_helper_rules(rs, _NLC)
    guards = [any("nfproto" in json.dumps(e) for e in r["expr"]) for r in added]
    assert guards == [False, True]


def test_unavailable_helper_is_skipped_with_warning() -> None:
    # Capability gating (AUTOHELPERS-equivalent): an unprovided helper is skipped with a warning
    # and nothing is emitted — the remaining ruleset is exactly the well-formed base skeleton.
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(),))
    with pytest.warns(UserWarning, match="ftp"):
        out = generate(rs, capabilities=HelperCapabilities())
    assert out == generate(Ruleset(zones=_NFW))


def test_default_capabilities_provide_nothing_so_helpers_are_skipped() -> None:
    # The generator defaults to the empty capability surface: a helper is emitted only when the
    # caller declares the platform provides it (fail-closed).
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(),))
    with pytest.warns(UserWarning, match="ftp"):
        out = generate(rs)
    assert not [c for c in out["nftables"] if "ct helper" in c["add"]]


def test_unknown_helper_name_fails_fast_even_if_marked_available() -> None:
    # A helper name absent from the built-in registry is malformed IR the generator cannot lower:
    # fail closed (ADR-0004), independent of the capability surface.
    rs = Ruleset(
        zones=_NFW,
        conntrack_helpers=(ConntrackHelper(name="bogus", source="net", dest="fw"),),
    )
    with pytest.raises(ConfigError) as exc:
        generate(rs, capabilities=HelperCapabilities(available=frozenset({"bogus"})))
    assert "bogus" in str(exc.value)


def test_object_deduped_when_a_helper_is_used_by_several_rows() -> None:
    rs = Ruleset(
        zones=_NLC,
        conntrack_helpers=(_ftp(source="net", dest="fw"), _ftp(source="loc", dest="fw")),
    )
    assert len(_cth_objects(rs)) == 1
    assert len(_added_helper_rules(rs, _NLC)) == 2


def test_object_is_emitted_before_the_rule_that_sets_it() -> None:
    # nft loads top-to-bottom: the object must exist before any rule references it.
    rs = Ruleset(zones=_NFW, conntrack_helpers=(_ftp(),))
    cmds = generate(rs, capabilities=_ALL_HELPERS)["nftables"]
    obj_idx = next(i for i, c in enumerate(cmds) if "ct helper" in c["add"])
    rule_idx = next(
        i
        for i, c in enumerate(cmds)
        if "rule" in c["add"] and c["add"]["rule"]["expr"][-1] == {"ct helper": "ftp"}
    )
    assert obj_idx < rule_idx


def test_assignment_rule_precedes_the_policy_default() -> None:
    # The non-terminal `ct helper set` must run before the zone-pair fall-through can drop it.
    rs = Ruleset(
        zones=_NFW,
        conntrack_helpers=(_ftp(),),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )
    rules = _cth_rules(rs)
    set_idx = next(i for i, r in enumerate(rules) if r["expr"][-1] == {"ct helper": "ftp"})
    drop_idx = next(i for i, r in enumerate(rules) if r["expr"][-1] == {"drop": None})
    assert set_idx < drop_idx


def test_ct_helpers_match_golden() -> None:
    rs = Ruleset(
        zones=_NLC,
        conntrack_helpers=(
            _ftp(source="net", dest="fw"),
            ConntrackHelper(name="pptp", source="net", dest="loc", family=Family.IPV4),
        ),
        policies=(Policy(source="all", dest="all", action="DROP"),),
    )

    def gen(r: Ruleset) -> dict[str, Any]:
        return generate(r, capabilities=_ALL_HELPERS)

    assert_golden(rs, "ct_helpers", generator=gen)
