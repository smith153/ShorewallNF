import json
from pathlib import Path
from typing import Any

import pytest

import tests.golden_harness as gh
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


# --- nft --check dry-run validation (task #165) ------------------------------
#
# ``nft --check`` reads the kernel ruleset cache and so needs CAP_NET_ADMIN (root); it cannot
# run in the fast unprivileged tier. These tests are marked ``nft`` and run in a dedicated
# privileged CI step (see ci.yml). ``require_nft`` makes a missing/broken nft a HARD failure
# under CI so the dry-run can never silently skip there, while skipping locally for dev
# convenience — replacing the old ``skipif(not python3-nftables)`` that skipped silently in CI.

# A rule added into a table/chain that was never created — a ruleset ``nft --check`` must reject.
_BROKEN_RULESET: dict[str, Any] = {
    "nftables": [
        {
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "snf_ghost",
                    "chain": "snf_ghost",
                    "expr": [{"accept": None}],
                }
            }
        }
    ]
}


@pytest.mark.nft
def test_generated_ruleset_passes_nft_check() -> None:
    gh.require_nft()  # hard-fails under CI if nft can't run; skips locally
    from shorewallnf.applier import check_ruleset

    validated = 0
    for fixture in (FIXTURE, POLICY_FIXTURE, RULES_FIXTURE):
        check_ruleset(cli.compile_config(fixture))  # raises ConfigError if nft rejects it
        validated += 1
    assert validated >= 1  # non-vacuous: at least one ruleset really passed nft --check


@pytest.mark.nft
def test_check_ruleset_rejects_a_broken_ruleset() -> None:
    gh.require_nft()  # negative control needs a working nft to reject against
    from shorewallnf.applier import check_ruleset
    from shorewallnf.errors import ConfigError

    with pytest.raises(ConfigError):
        check_ruleset(_BROKEN_RULESET)


# --- the CI-aware gate itself (hermetic: no nft needed) ----------------------


def test_require_nft_hard_fails_under_ci_when_nft_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under CI a missing/broken nft must FAIL, never skip — the guard against a silent all-skip.
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(gh, "nft_available", lambda: False)
    with pytest.raises(AssertionError, match="must run in CI"):
        gh.require_nft()


def test_require_nft_skips_locally_when_nft_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Off CI, a missing nft skips for dev convenience rather than failing the developer's run.
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(gh, "nft_available", lambda: False)
    with pytest.raises(pytest.skip.Exception):
        gh.require_nft()


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
    # harness also dry-run validates the output with nft --check where nft can run.
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
    # harness also dry-run validates the output with nft --check where nft can run.
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


# --- NAT (DNAT) end-to-end (#145) --------------------------------------------
#
# A committed dual-stack fixture mirroring the reference config's DNAT intent with RFC 5737 /
# RFC 3849 documentation addresses only: a port-forward, a port range, a `:port` remap, and an
# IPv6 global-address ACCEPT (no NAT, ADR-0002). Kept in its own region so it doesn't interleave
# with the tests above.

NAT_FIXTURE = Path(__file__).parent / "fixtures" / "nat_compile_dir"


def test_nat_compile_end_to_end_matches_golden() -> None:
    # Full path: preprocess (I/O) -> parse_config (nats wired in) -> generate. The golden harness
    # also dry-run validates the output with nft --check where nft can run.
    assert_golden(parse_config(cli.preprocess(NAT_FIXTURE)), "nat_compile")


def test_nat_compile_config_carries_dnat_and_v6_accept_through() -> None:
    # compile_config runs the whole pipeline (preprocess -> parse -> validate -> generate); the
    # DNAT `Nat` entries must surface as v4 nat + forward-accept rules and a v6 direct ACCEPT,
    # alongside the base skeleton, the filter rule, and the policy defaults.
    compiled = cli.compile_config(NAT_FIXTURE)
    adds = compiled["nftables"]
    # The nat table skeleton is present (the v4 DNATs need it, ADR-0008)...
    assert {"add": {"table": {"family": "inet", "name": "nat"}}} in adds
    rules = [c["add"]["rule"] for c in adds if "rule" in c["add"]]
    # ...the three v4 DNATs compile to nat prerouting `dnat` rules (single, range, remap)...
    prerouting = [r for r in rules if r["table"] == "nat" and r["chain"] == "prerouting"]
    dnats = [e["dnat"] for r in prerouting for e in r["expr"] if "dnat" in e]
    assert len(dnats) == 3
    assert {"addr": "203.0.113.30", "family": "ip", "port": 8022} in dnats  # the :port remap
    # ...and the IPv6 DNAT is a plain forward ACCEPT to the global v6 address (no NAT, ADR-0002).
    forward = [r for r in rules if r["table"] == "filter" and r["chain"] == "forward"]
    v6_daddr = {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": "ip6", "field": "daddr"}},
            "right": "2001:db8::5",
        }
    }
    assert any(v6_daddr in r["expr"] and r["expr"][-1] == {"accept": None} for r in forward)
    # The v6 address never leaks into the nat table (IPv6 does no NAT).
    assert not any(r["table"] == "nat" and "2001:db8::5" in json.dumps(r) for r in rules)


@pytest.mark.nft
def test_nat_compiled_ruleset_passes_nft_check() -> None:
    gh.require_nft()  # hard-fails under CI if nft can't run; skips locally
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(NAT_FIXTURE))  # must not raise


# --- source NAT (SNAT/MASQUERADE) end-to-end (#158) --------------------------
#
# A committed IPv4 fixture mirroring the reference config's outbound-NAT intent with RFC 5737
# documentation ranges and generic interface names: masquerade a LAN subnet out the WAN egress
# interface, plus one static SNAT to a fixed source address (ADR-0009). A DNAT port-forward sits
# alongside it, so the postrouting source-NAT rules are proven to compile beside the prerouting
# DNAT (ADR-0008) in one ruleset. Kept in its own region so it doesn't interleave with the above.

SNAT_FIXTURE = Path(__file__).parent / "fixtures" / "snat_compile_dir"


def test_snat_compile_end_to_end_matches_golden() -> None:
    # Full path: preprocess (I/O) -> parse_config (snat wired in) -> generate. The golden harness
    # also dry-run validates the output with nft -c where python3-nftables is available.
    assert_golden(parse_config(cli.preprocess(SNAT_FIXTURE)), "snat_compile")


def test_snat_compile_config_carries_masquerade_and_snat_through() -> None:
    # compile_config runs the whole pipeline (preprocess -> parse -> validate -> generate); the
    # MASQUERADE/SNAT `Nat` entries must surface as nat postrouting source-NAT rules, alongside
    # the DNAT prerouting rule, the base skeleton, the filter rules, and the policy defaults.
    compiled = cli.compile_config(SNAT_FIXTURE)
    adds = compiled["nftables"]
    # The nat table skeleton is present (the source-NAT + DNAT entries need it, ADR-0008)...
    assert {"add": {"table": {"family": "inet", "name": "nat"}}} in adds
    rules = [c["add"]["rule"] for c in adds if "rule" in c["add"]]
    # ...the MASQUERADE and explicit SNAT compile to nat postrouting source-NAT rules...
    postrouting = [r for r in rules if r["table"] == "nat" and r["chain"] == "postrouting"]
    targets = [e for r in postrouting for e in r["expr"] if "masquerade" in e or "snat" in e]
    assert {"masquerade": None} in targets  # dynamic source NAT to the egress address
    assert {"snat": {"addr": "203.0.113.5", "family": "ip"}} in targets  # static SNAT(<addr>)
    # ...source NAT emits no forward accept (ADR-0009 §5) — the postrouting rules carry only
    # oifname + ip saddr + the source-NAT target, never an accept verdict...
    assert all(not any("accept" in expr for expr in r["expr"]) for r in postrouting)
    # ...and the DNAT still compiles to a prerouting dnat rule beside the source-NAT rules.
    prerouting = [r for r in rules if r["table"] == "nat" and r["chain"] == "prerouting"]
    assert any("dnat" in expr for r in prerouting for expr in r["expr"])


@pytest.mark.skipif(
    not _nft_available(),
    reason="python3-nftables not installed (behavioral netns tier, #77/#78)",
)
def test_snat_compiled_ruleset_passes_nft_check() -> None:
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(SNAT_FIXTURE))  # must not raise
