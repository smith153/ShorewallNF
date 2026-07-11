"""Netns behavioral proof of the read-only introspection invariant (#410, ADR-0065).

`show rules` reads the live ruleset through a `list`-only seam that has no mutating form. This
loads a real ruleset into the firewall host (the router namespace), snapshots the live ruleset,
runs `shorewallnf show rules` inside that namespace, and asserts the ruleset is **byte-for-byte
unchanged** — the query never alters what it inspects. Gated on the `netns` marker + root, so it
skips cleanly in the hermetic tier (epics #77/#78).
"""

from __future__ import annotations

import sys

import pytest

from shorewallnf.ir import Family, Policy, Rule, Ruleset, Zone, ZoneMember
from tests import netns_harness as nh

_CLIENT = nh.Endpoint(
    name="snf410_cli", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_TOPO = nh.Topology(router="snf410_r", endpoints=(_CLIENT,))
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="loc", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
)
_RULES = (Rule(action="ACCEPT", source="loc", dest="fw", proto="tcp", dport="22"),)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


@pytest.mark.netns
@_requires_netns
def test_show_rules_leaves_the_live_ruleset_byte_for_byte_unchanged() -> None:
    rs = Ruleset(zones=_ZONES, policies=(Policy("loc", "fw", "DROP"),), rules=_RULES)
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(rs)
        before = sb.exec(_TOPO.router, ["nft", "--json", "list", "ruleset"]).stdout
        # Drive the real CLI dispatch (list_ruleset query -> renderer) inside the namespace.
        show = "import sys; from shorewallnf.cli import main; sys.exit(main(['show', 'rules']))"
        result = sb.exec(_TOPO.router, [sys.executable, "-c", show])
        after = sb.exec(_TOPO.router, ["nft", "--json", "list", "ruleset"]).stdout

        assert result.returncode == 0
        assert "Table: inet filter" in result.stdout  # the query really rendered live rules
        assert after == before  # read-only: the introspection changed nothing
