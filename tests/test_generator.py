import json
from pathlib import Path
from typing import Any

from shorewallnf.generator import generate
from shorewallnf.ir import Ruleset

GOLDEN = Path(__file__).parent / "golden" / "base_skeleton.json"


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
