import json
from pathlib import Path
from typing import Any

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.generator import generate
from shorewallnf.ir import Family, Policy, Ruleset, Zone, ZoneMember

GOLDEN = Path(__file__).parent / "golden" / "base_skeleton.json"
POLICY_GOLDEN = Path(__file__).parent / "golden" / "policy_default_rules.json"


def test_base_skeleton_matches_golden() -> None:
    assert generate(Ruleset()) == json.loads(GOLDEN.read_text())


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
