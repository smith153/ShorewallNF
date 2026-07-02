import json
from pathlib import Path

import pytest

from shorewallnf import cli
from shorewallnf.ir import Family, Nat, Policy, Rule, ZoneMember
from shorewallnf.parser import parse_config
from shorewallnf.preprocessor import SourceLine, to_source_lines
from tests.golden_harness import assert_golden

FIXTURE = Path(__file__).parent / "fixtures" / "compile_dir"
POLICY_FIXTURE = Path(__file__).parent / "fixtures" / "policy_compile_dir"
RULES_FIXTURE = Path(__file__).parent / "fixtures" / "rules_compile_dir"
GOLDEN = Path(__file__).parent / "golden" / "base_skeleton.json"


def _streams(**files: str) -> dict[str, list[SourceLine]]:
    return {name: to_source_lines(text, name) for name, text in files.items()}


# --- parse_config: assemble the Ruleset --------------------------------------


def test_parse_config_assembles_zones_interfaces_and_membership() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth0 detect\nloc eth1 detect\n",
        )
    )
    by_name = {z.name: z for z in ruleset.zones}
    assert by_name["fw"].is_firewall is True
    assert by_name["net"].members == (ZoneMember(interface="eth0", family=Family.BOTH),)
    assert by_name["loc"].members == (ZoneMember(interface="eth1", family=Family.BOTH),)
    assert {i.name for i in ruleset.interfaces} == {"eth0", "eth1"}


def test_parse_config_empty_streams_gives_empty_ruleset() -> None:
    ruleset = parse_config({})
    assert ruleset.zones == () and ruleset.interfaces == ()


# --- compile_config + the compile verb ---------------------------------------


def test_compile_config_emits_base_skeleton() -> None:
    assert cli.compile_config(FIXTURE) == json.loads(GOLDEN.read_text())


def test_compile_verb_emits_json_ruleset(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compile", str(FIXTURE)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted == json.loads(GOLDEN.read_text())


def test_compile_verb_reports_a_missing_config_dir(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compile", "no-such-compile-dir"]) == 1
    assert "error:" in capsys.readouterr().err


# --- nft -c validation (gated on python3-nftables) ---------------------------


def _nft_available() -> bool:
    try:
        import nftables  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(
    not _nft_available(),
    reason="python3-nftables not installed (behavioral netns tier, #77/#78)",
)
def test_generated_ruleset_passes_nft_check() -> None:
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(FIXTURE))  # must not raise


# --- policies end-to-end (#91) -----------------------------------------------


def test_parse_config_parses_the_policy_file() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth1 detect\nloc eth0 detect\n",
            policy="loc net ACCEPT\nall all REJECT info\n",
        )
    )
    assert ruleset.policies == (
        Policy(source="loc", dest="net", action="ACCEPT"),
        Policy(source="all", dest="all", action="REJECT", log_level="info"),
    )


def test_policy_compile_end_to_end_matches_golden() -> None:
    # Full path: preprocess (I/O) -> parse_config (policy wired in) -> generate. The golden
    # harness also dry-run validates the output with nft -c where python3-nftables is available.
    assert_golden(parse_config(cli.preprocess(POLICY_FIXTURE)), "policy_compile")


def test_policy_compile_emits_ordered_inter_zone_rules() -> None:
    compiled = cli.compile_config(POLICY_FIXTURE)
    rules = [c["add"]["rule"] for c in compiled["nftables"] if "rule" in c["add"]]
    forward = [r for r in rules if r["chain"] == "forward"]
    iif_loc = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}
    # loc(eth0) -> net(eth1) ACCEPT is emitted as a forward rule...
    assert any(iif_loc in r["expr"] and r["expr"][-1] == {"accept": None} for r in forward)
    # ...and the wildcard `all all REJECT info` is the final forward rule (fail-closed order).
    assert forward[-1]["expr"] == [{"log": {"level": "info"}}, {"reject": None}]


# --- rules end-to-end (#125) -------------------------------------------------


def test_parse_config_parses_the_rules_file() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth1 detect\nloc eth0 detect\n",
            rules="ACCEPT net fw tcp 22\nACCEPT loc net udp 53\n",
        )
    )
    assert ruleset.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22"),
        Rule(action="ACCEPT", source="loc", dest="net", proto="udp", dport="53"),
    )


def test_rules_compile_end_to_end_matches_golden() -> None:
    # Full path: preprocess (I/O) -> parse_config (rules wired in) -> generate. The golden
    # harness also dry-run validates the output with nft -c where python3-nftables is available.
    assert_golden(parse_config(cli.preprocess(RULES_FIXTURE)), "rules_compile")


def test_rules_compile_places_feature_rules_before_policy_defaults() -> None:
    compiled = cli.compile_config(RULES_FIXTURE)
    rules = [c["add"]["rule"] for c in compiled["nftables"] if "rule" in c["add"]]
    input_rules = [r for r in rules if r["chain"] == "input"]
    # the explicit `net fw tcp 22 ACCEPT` reaches the input chain as a dport-22 accept...
    left = {"payload": {"protocol": "tcp", "field": "dport"}}
    dport22 = {"match": {"op": "==", "left": left, "right": 22}}
    assert any(dport22 in r["expr"] and r["expr"][-1] == {"accept": None} for r in input_rules)
    # ...and the wildcard `all all REJECT info` is the final forward rule (fail-closed order).
    forward = [r for r in rules if r["chain"] == "forward"]
    assert forward[-1]["expr"] == [{"log": {"level": "info"}}, {"reject": None}]


def test_parse_config_parses_dnat_rules_into_nats() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth1 detect\nloc eth0 detect\n",
            rules="ACCEPT net fw tcp 22\nDNAT net loc:192.0.2.5:8022 tcp 22\n",
        )
    )
    assert ruleset.rules == (
        Rule(action="ACCEPT", source="net", dest="fw", proto="tcp", dport="22"),
    )
    assert ruleset.nats == (
        Nat(
            action="DNAT", source="net", dest="loc", to="192.0.2.5:8022",
            proto="tcp", dport="22", family=Family.IPV4,
        ),
    )


def test_parse_config_parses_the_snat_file() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth1 detect\nloc eth0 detect\n",
            snat="MASQUERADE 10.0.0.0/8 eth1\nSNAT(203.0.113.5) 192.0.2.0/24 eth1\n",
        )
    )
    assert ruleset.nats == (
        Nat(
            action="MASQUERADE", source_nets="10.0.0.0/8", out_interface="eth1",
            family=Family.IPV4,
        ),
        Nat(
            action="SNAT", source_nets="192.0.2.0/24", out_interface="eth1",
            snat_to="203.0.113.5", family=Family.IPV4,
        ),
    )


def test_parse_config_combines_dnat_and_snat_nats() -> None:
    # DNAT entries from `rules` come first, then the `snat` file's source-NAT entries.
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth1 detect\nloc eth0 detect\n",
            rules="DNAT net loc:192.0.2.5 tcp 22\n",
            snat="MASQUERADE 10.0.0.0/8 eth1\n",
        )
    )
    assert [nat.action for nat in ruleset.nats] == ["DNAT", "MASQUERADE"]
