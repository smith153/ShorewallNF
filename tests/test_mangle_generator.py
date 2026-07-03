"""Tests for mangle compilation (#229, ADR-0042).

A :class:`~shorewallnf.ir.MangleRule` lowers into a rule in the ``inet filter`` **prerouting**
mangle chain (``type filter hook prerouting priority -150``): MARK/CONNMARK set the packet/conn
mark (masked as a read-modify-write), DIVERT keeps an established transparent-proxy socket local,
and TPROXY redirects to a local port (family-scoped). A DEST given as a bare zone fails closed
(the out-interface isn't known at prerouting). File order is preserved.
"""

from typing import Any

import pytest

import tests.golden_harness as gh
from shorewallnf.errors import ConfigError
from shorewallnf.generator import generate
from shorewallnf.ir import Family, Interface, MangleRule, Ruleset, Zone, ZoneMember

_ZONES = (
    Zone(name="net", members=(ZoneMember(interface="eth0", family=Family.BOTH),)),
    Zone(name="loc", members=(ZoneMember(interface="eth1", family=Family.BOTH),)),
    Zone(name="fw", is_firewall=True),
)
_IFACES = (Interface(name="eth0"), Interface(name="eth1"))


def _cmds(*rules: MangleRule) -> list[dict[str, Any]]:
    return generate(Ruleset(zones=_ZONES, interfaces=_IFACES, mangle_rules=rules))["nftables"]


def _chains(cmds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [c["add"]["chain"] for c in cmds if "chain" in c.get("add", {})]


def _prerouting_rules(cmds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        c["add"]["rule"]
        for c in cmds
        if "rule" in c.get("add", {}) and c["add"]["rule"]["chain"] == "prerouting"
    ]


def _iif(name: str) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": name}}


def _socket_match() -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"socket": {"key": "transparent"}}, "right": 1}}


def _nfproto(value: str) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": value}}


# --- the prerouting mangle chain ---------------------------------------------


def test_prerouting_mangle_chain_emitted_when_rules_present() -> None:
    ch = next(c for c in _chains(_cmds(MangleRule(action="MARK", source="net", mark=1)))
              if c["name"] == "prerouting")
    assert ch == {
        "family": "inet", "table": "filter", "name": "prerouting",
        "type": "filter", "hook": "prerouting", "prio": -150, "policy": "accept",
    }


def test_no_mangle_chain_without_rules() -> None:
    cmds = generate(Ruleset(zones=_ZONES))["nftables"]
    assert not any(c["name"] == "prerouting" for c in _chains(cmds))


# --- MARK / CONNMARK ---------------------------------------------------------


def test_mark_sets_meta_mark() -> None:
    (rule,) = _prerouting_rules(_cmds(MangleRule(action="MARK", source="net", mark=1)))
    mark = {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 1}}
    assert rule["expr"] == [_iif("eth0"), mark]


def test_connmark_sets_ct_mark() -> None:
    (rule,) = _prerouting_rules(_cmds(MangleRule(action="CONNMARK", source="net", mark=2)))
    assert rule["expr"][-1] == {"mangle": {"key": {"ct": {"key": "mark"}}, "value": 2}}


def test_mark_with_mask_is_a_read_modify_write() -> None:
    (rule,) = _prerouting_rules(_cmds(MangleRule(action="MARK", source="net", mark=1, mask=0xFF)))
    assert rule["expr"][-1] == {
        "mangle": {"key": {"meta": {"key": "mark"}},
                   "value": {"|": [{"&": [{"meta": {"key": "mark"}}, 0xFFFFFF00]}, 1]}}
    }


# --- DIVERT ------------------------------------------------------------------


def test_divert_matches_transparent_socket_and_accepts() -> None:
    (rule,) = _prerouting_rules(_cmds(MangleRule(action="DIVERT", source="net", proto="tcp")))
    assert _socket_match() in rule["expr"]
    assert rule["expr"][-1] == {"accept": None}


# --- TPROXY ------------------------------------------------------------------


def test_tproxy_emits_family_scoped_statement_and_accepts() -> None:
    (rule,) = _prerouting_rules(_cmds(
        MangleRule(action="TPROXY", source="net", proto="tcp", dport="80",
                   port=1080, family=Family.IPV4)))
    assert {"tproxy": {"family": "ip", "port": 1080}} in rule["expr"]
    assert _nfproto("ipv4") in rule["expr"]
    assert rule["expr"][-1] == {"accept": None}


def test_tproxy_without_a_concrete_family_fails_closed() -> None:
    with pytest.raises(ConfigError, match="TPROXY"):
        _cmds(MangleRule(action="TPROXY", source="net", proto="tcp", port=1080, family=Family.BOTH))


# --- fail closed / dest handling ---------------------------------------------


def test_bare_zone_dest_fails_closed() -> None:
    with pytest.raises(ConfigError, match="out-interface"):
        _cmds(MangleRule(action="MARK", source="net", dest="loc", mark=1))


def test_firewall_zone_source_fails_closed() -> None:
    # A firewall zone as SOURCE is locally-originated traffic — not present at prerouting — so the
    # rule can't be lowered here; fail closed rather than silently marking all forwarded traffic.
    with pytest.raises(ConfigError, match="firewall"):
        _cmds(MangleRule(action="MARK", source="fw", mark=1))


def test_firewall_zone_dest_fails_closed() -> None:
    # A firewall zone as DEST would need the firewall's own addresses / the routing decision; fail
    # closed rather than silently dropping the dest constraint and marking all traffic from SOURCE.
    with pytest.raises(ConfigError, match="firewall"):
        _cmds(MangleRule(action="MARK", source="net", dest="fw", mark=1))


def test_mangle_fail_closed_error_is_located() -> None:
    # The generator threads the rule's source location (#256) into its fail-closed errors.
    with pytest.raises(ConfigError) as exc:
        _cmds(MangleRule(action="MARK", source="fw", mark=1, path="mangle", line=7))
    assert str(exc.value).startswith("mangle:7: ")


def test_host_dest_matches_daddr() -> None:
    (rule,) = _prerouting_rules(_cmds(
        MangleRule(action="MARK", source="net", dest="loc:192.0.2.10", mark=1, family=Family.IPV4)))
    assert {"match": {"op": "==",
                      "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                      "right": "192.0.2.10"}} in rule["expr"]


# --- file order --------------------------------------------------------------


def test_rules_emitted_in_file_order() -> None:
    rules = _prerouting_rules(_cmds(
        MangleRule(action="MARK", source="net", mark=1),
        MangleRule(action="CONNMARK", source="loc", mark=2),
    ))
    assert _iif("eth0") in rules[0]["expr"]
    assert _iif("eth1") in rules[1]["expr"]


# --- nft --check validates the generated schema (CI privileged tier; skips locally) ---


@pytest.mark.nft
def test_mangle_ruleset_passes_nft_check() -> None:
    # The schema guarantee for #229: the mangle/tproxy/socket JSON loads under `nft --check`.
    # Hard-fails under CI if nft can't run; skips locally (needs CAP_NET_ADMIN).
    gh.require_nft()
    from shorewallnf.applier import check_ruleset

    rs = Ruleset(zones=_ZONES, interfaces=_IFACES, mangle_rules=(
        MangleRule(action="MARK", source="net", mark=1),
        MangleRule(action="CONNMARK", source="loc", mark=2, mask=0xFF),
        MangleRule(action="DIVERT", source="net", proto="tcp"),
        MangleRule(action="TPROXY", source="net", proto="tcp", dport="80",
                   port=1080, family=Family.IPV4),
    ))
    check_ruleset(generate(rs))  # must not raise
