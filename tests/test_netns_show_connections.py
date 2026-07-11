"""Netns behavioral proof of the read-only conntrack-introspection invariant (#412, ADR-0065).

`show connections` reads live kernel state through a `conntrack -L` seam that has no mutating
form. This loads a real ruleset into the firewall host (the router namespace), drives a little
traffic so the kernel tracks a flow, snapshots the live nft ruleset, runs `shorewallnf show
connections` inside that namespace, and asserts the ruleset is **byte-for-byte unchanged** — the
query never alters what it inspects. Gated on the `netns` marker + root + a `conntrack` binary, so
it skips cleanly in the hermetic tier (epics #77/#78).
"""

from __future__ import annotations

import shutil
import sys

import pytest

from shorewallnf.ir import Family, Policy, Rule, Ruleset, Zone, ZoneMember
from tests import netns_harness as nh

_CLIENT = nh.Endpoint(
    name="snf412_cli", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_TOPO = nh.Topology(router="snf412_r", endpoints=(_CLIENT,))
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="loc", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
)
# An established/related accept makes the kernel conntrack the flow the ping below generates.
_RULES = (Rule(action="ACCEPT", source="loc", dest="fw", proto="icmp"),)

_requires_conntrack = pytest.mark.skipif(
    not (nh.netns_available() and shutil.which("conntrack") is not None),
    reason="netns conntrack tier needs root + ip/nft + the conntrack binary (epics #77/#78)",
)


@pytest.mark.netns
@_requires_conntrack
def test_show_connections_leaves_the_live_ruleset_byte_for_byte_unchanged() -> None:
    rs = Ruleset(zones=_ZONES, policies=(Policy("loc", "fw", "DROP"),), rules=_RULES)
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(rs)
        sb.ping(_CLIENT.name, _CLIENT.gateway4)  # generate a flow for the kernel to track
        before = sb.exec(_TOPO.router, ["nft", "--json", "list", "ruleset"]).stdout
        # Drive the real CLI dispatch (list_connections query -> renderer) inside the namespace.
        show = (
            "import sys; from shorewallnf.cli import main; "
            "sys.exit(main(['show', 'connections']))"
        )
        result = sb.exec(_TOPO.router, [sys.executable, "-c", show])
        after = sb.exec(_TOPO.router, ["nft", "--json", "list", "ruleset"]).stdout

        assert result.returncode == 0
        assert "Connections" in result.stdout  # the query really rendered the connection report
        assert after == before  # read-only: the introspection changed nothing