import json
from pathlib import Path
from typing import Any

import pytest

import tests.golden_harness as gh
from shorewallnf import cli
from shorewallnf.generator import generate, generate_routing
from shorewallnf.ir import (
    ConntrackHelper,
    Family,
    HelperCapabilities,
    Nat,
    Policy,
    RoutingArtifact,
    Rule,
    Ruleset,
    ZoneMember,
)
from shorewallnf.parser import parse_config
from shorewallnf.preprocessor import SourceLine, to_source_lines
from shorewallnf.validator import validate
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


# --- macro/action resolution end-to-end (#184) -------------------------------
#
# A fixture whose `rules` invoke both a built-in macro (`Web`) and a site-defined
# `action.Ssh`. The resolver (ADR-0020) expands both into verdict rules before the validator
# and generator run, so the whole pipeline compiles and passes `nft -c`.

MACRO_FIXTURE = Path(__file__).parent / "fixtures" / "macro_compile_dir"


def test_macro_compile_expands_builtin_and_site_actions() -> None:
    compiled = cli.compile_config(MACRO_FIXTURE)
    rules = [c["add"]["rule"] for c in compiled["nftables"] if "rule" in c["add"]]
    input_rules = [r for r in rules if r["chain"] == "input"]
    dport = {"payload": {"protocol": "tcp", "field": "dport"}}

    def accepts_port(port: int) -> bool:
        match = {"match": {"op": "==", "left": dport, "right": port}}
        return any(match in r["expr"] and r["expr"][-1] == {"accept": None} for r in input_rules)

    # `Web` (built-in) expands to tcp 80 + tcp 443; `Ssh` (site action) expands to tcp 22.
    assert accepts_port(80) and accepts_port(443) and accepts_port(22)


@pytest.mark.nft
def test_macro_compiled_ruleset_passes_nft_check() -> None:
    gh.require_nft()  # hard-fails under CI if nft can't run; skips locally
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(MACRO_FIXTURE))  # must not raise


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


def test_parse_config_carries_conntrack_helpers() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth1 detect\nloc eth0 detect\n",
            conntrack="CT:helper:ftp - -\nCT:helper:pptp - -\n",
        )
    )
    assert ruleset.conntrack_helpers == (
        ConntrackHelper(name="ftp", proto="tcp", dport="21", family=Family.BOTH),
        ConntrackHelper(name="pptp", proto="tcp", dport="1723", family=Family.IPV4),
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
    not gh.nft_available(),
    reason="python3-nftables not installed (behavioral netns tier, #77/#78)",
)
def test_snat_compiled_ruleset_passes_nft_check() -> None:
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(SNAT_FIXTURE))  # must not raise


# --- conntrack helpers end-to-end (#222) -------------------------------------
#
# A committed fixture mirroring the reference config's helper intent abstractly: the active-FTP
# helper on the FTP control channel narrowed to an RFC 5737 host (v4-scoped), a dual-stack TFTP
# helper, and the IPv4-only PPTP helper (RFC ranges only). The generator gates emission on a
# compile-time HelperCapabilities surface (ADR-0040/0041); the CLI path defaults to the empty
# surface, so the caller here declares the platform provides them. The capability-on golden shows
# the `ct helper` objects + assignment rules; a capability-off variant skips the unavailable helper
# with a warning yet still compiles to a valid ruleset. Kept in its own region.

CONNTRACK_FIXTURE = Path(__file__).parent / "fixtures" / "conntrack_compile_dir"

# The AUTOHELPERS-equivalent surface that makes every fixture helper available (ADR-0040).
_CONNTRACK_CAPS = HelperCapabilities(available=frozenset({"ftp", "tftp", "pptp"}))

# The meta nfproto guard a family-scoped helper's assignment rule carries (ADR-0002).
_NFPROTO_V4 = {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}


def _helper_objects(compiled: dict[str, Any]) -> list[dict[str, Any]]:
    return [c["add"]["ct helper"] for c in compiled["nftables"] if "ct helper" in c["add"]]


def _helper_assignment_rules(compiled: dict[str, Any]) -> list[dict[str, Any]]:
    rules = (c["add"]["rule"] for c in compiled["nftables"] if "rule" in c["add"])
    return [r for r in rules if any("ct helper" in e for e in r["expr"])]


def test_conntrack_compile_end_to_end_matches_golden() -> None:
    # Full path: preprocess (I/O) -> parse_config (conntrack_helpers wired in) -> generate with the
    # helpers made available. The golden harness also dry-run validates with nft --check where able.
    ruleset = parse_config(cli.preprocess(CONNTRACK_FIXTURE))
    assert_golden(ruleset, "conntrack_compile", generator=lambda rs: generate(rs, _CONNTRACK_CAPS))


def test_conntrack_compile_carries_helper_objects_and_assignment_rules() -> None:
    # parse_config -> generate with the platform providing all three helpers. One `ct helper` object
    # per distinct helper (v6-capable -> l3proto inet, v4-only -> l3proto ip) precedes one
    # `ct helper set` assignment rule per row (ADR-0041), alongside the base skeleton and filters.
    compiled = generate(parse_config(cli.preprocess(CONNTRACK_FIXTURE)), _CONNTRACK_CAPS)
    adds = compiled["nftables"]
    objects = {o["name"]: o for o in _helper_objects(compiled)}
    assert objects["ftp"]["protocol"] == "tcp" and objects["ftp"]["l3proto"] == "inet"
    assert objects["tftp"]["protocol"] == "udp" and objects["tftp"]["l3proto"] == "inet"
    assert objects["pptp"]["protocol"] == "tcp" and objects["pptp"]["l3proto"] == "ip"  # v4-only
    # ...one assignment rule per row binds its helper via the non-terminal set statement...
    rules = _helper_assignment_rules(compiled)
    assigned = {e["ct helper"] for r in rules for e in r["expr"] if "ct helper" in e}
    assert assigned == {"ftp", "tftp", "pptp"}
    # ...the v4-narrowed FTP rule carries the RFC 5737 host match + a meta nfproto ipv4 guard...
    ftp_rule = next(r for r in rules if {"ct helper": "ftp"} in r["expr"])
    assert _NFPROTO_V4 in ftp_rule["expr"]
    host_match = {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": "ip", "field": "daddr"}},
            "right": "198.51.100.10",
        }
    }
    assert host_match in ftp_rule["expr"]
    # ...while the dual-stack TFTP rule needs no family guard (ADR-0002)...
    tftp_rule = next(r for r in rules if {"ct helper": "tftp"} in r["expr"])
    assert _NFPROTO_V4 not in tftp_rule["expr"]
    # ...and every `ct helper` object is emitted before the assignment rules that reference it.
    last_obj_idx = max(i for i, c in enumerate(adds) if "ct helper" in c["add"])
    first_rule_idx = min(
        i
        for i, c in enumerate(adds)
        if "rule" in c["add"] and any("ct helper" in e for e in c["add"]["rule"]["expr"])
    )
    assert last_obj_idx < first_rule_idx


def test_conntrack_capability_off_helper_is_skipped_with_warning() -> None:
    # A helper the platform does not provide is skipped — no object, no rule — with a surfaced
    # warning, leaving the rest of the ruleset well-formed (ADR-0041 fail-closed capability gating).
    ruleset = parse_config(cli.preprocess(CONNTRACK_FIXTURE))
    caps = HelperCapabilities(available=frozenset({"ftp", "pptp"}))  # tftp marked unavailable
    with pytest.warns(UserWarning, match="tftp.*not available"):
        compiled = generate(ruleset, caps)
    assert {o["name"] for o in _helper_objects(compiled)} == {"ftp", "pptp"}
    assigned = {
        e["ct helper"]
        for r in _helper_assignment_rules(compiled)
        for e in r["expr"]
        if "ct helper" in e
    }
    assert assigned == {"ftp", "pptp"}


@pytest.mark.nft
def test_conntrack_compiled_ruleset_passes_nft_check() -> None:
    # The real end-to-end guarantee (#222): the generated `ct helper` objects + assignment rules
    # load under `nft --check`. Hard-fails under CI if nft can't run; skips locally (needs root).
    # Both the capability-on ruleset and a capability-off variant must validate.
    gh.require_nft()
    from shorewallnf.applier import check_ruleset

    ruleset = parse_config(cli.preprocess(CONNTRACK_FIXTURE))
    check_ruleset(generate(ruleset, _CONNTRACK_CAPS))  # objects + assignment rules
    with pytest.warns(UserWarning, match="not available"):
        capability_off = generate(ruleset, HelperCapabilities(available=frozenset({"ftp", "pptp"})))
    check_ruleset(capability_off)  # a skipped helper still leaves a valid ruleset


# --- providers / policy routing end-to-end (#236) ----------------------------
#
# A committed multi-uplink fixture (two IPv4 providers + one IPv6 path, RFC 5737 / RFC 3849)
# compiles preprocess -> parse_config -> validate -> generate_routing into the policy-routing
# artifacts (ADR-0050). The nft channel stays free of provider rules — providers emit no nft hook
# (the mark is owned by the mangle epic) — and still passes nft --check. Kept in its own region.

PROVIDERS_FIXTURE = Path(__file__).parent / "fixtures" / "providers_compile_dir"


def _providers_ruleset() -> Ruleset:
    # The compile pre-generation path: preprocess (I/O) -> parse_config -> validate.
    return validate(parse_config(cli.preprocess(PROVIDERS_FIXTURE)))


def _routing_dict(ruleset: Ruleset) -> dict[str, list[dict[str, object]]]:
    return {
        "routing": [
            {
                "table_id": a.table_id,
                "fwmark": a.fwmark,
                "gateway": a.gateway,
                "interface": a.interface,
                "family": a.family.value,
            }
            for a in generate_routing(ruleset)
        ]
    }


def test_providers_compile_routing_matches_golden() -> None:
    # Full path -> the policy-routing artifacts (the second output channel, not nftables JSON).
    assert_golden(
        _providers_ruleset(), "providers_compile_routing",
        check_nft=False, generator=_routing_dict,
    )


def test_providers_compile_carries_the_expected_routing() -> None:
    assert generate_routing(_providers_ruleset()) == (
        RoutingArtifact(table_id=1, fwmark=1, gateway="192.0.2.1",
                        interface="eth0", family=Family.IPV4),
        RoutingArtifact(table_id=2, fwmark=2, gateway="198.51.100.1",
                        interface="eth1", family=Family.IPV4),
        RoutingArtifact(table_id=3, fwmark=3, gateway="2001:db8::1",
                        interface="eth2", family=Family.IPV6),
    )


def test_providers_add_no_nft_rule() -> None:
    # ADR-0050: providers emit no nft mark hook, so the nft channel is identical with or without
    # the providers file — routing lives entirely in the iproute2 artifacts.
    from shorewallnf.resolver import resolve

    with_providers = cli.compile_config(PROVIDERS_FIXTURE)
    streams = cli.preprocess(PROVIDERS_FIXTURE)
    del streams["providers"]
    without_providers = generate(validate(resolve(parse_config(streams))))
    assert with_providers == without_providers


@pytest.mark.nft
def test_providers_compiled_nft_ruleset_passes_nft_check() -> None:
    # The nft channel a providers config produces (base skeleton + policy, no provider rule) loads
    # under nft --check. Hard-fails under CI if nft can't run; skips locally (needs root).
    gh.require_nft()
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(PROVIDERS_FIXTURE))  # must not raise
