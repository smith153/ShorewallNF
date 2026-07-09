"""Netns behavioral proof of DISABLE_IPV6 in the stopped safe state (#376, ADR-0061/ADR-0002).

The stopped safe state (:func:`shorewallnf.generator.generate_stopped`) must honor DISABLE_IPV6
exactly as the running ruleset does: a base ``meta nfproto ipv6 drop`` at the head of every base
chain, so a ``DISABLE_IPV6=Yes`` firewall stays IPv4-only *while stopped* too. This drives real
ICMP probes at the firewall host (the router namespace) over a dual-stack admin client whose
family-agnostic ``both`` admin rule would otherwise admit both families: with the gate on, the
declared IPv4 admin traffic still reaches the host while all IPv6 is dropped by the base drop; with
the gate off both families pass — proving the base drop, not the topology, is what blocks IPv6.
Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78).
"""

from __future__ import annotations

import pytest

from shorewallnf.generator import generate_stopped
from shorewallnf.ir import Family, Rule, Ruleset, Settings, Zone, ZoneMember
from tests import netns_harness as nh

# A dual-stack admin client wired to the firewall host (the router namespace): RFC 5737 IPv4 +
# RFC 3849 IPv6 documentation ranges, unique names so the sandbox cannot collide with other tests.
LOC = nh.Endpoint(
    name="snf376_loc",
    iface="v_loc",
    peer="p_loc",
    addr4="192.0.2.2/24",
    router4="192.0.2.1/24",
    addr6="2001:db8::2/64",
    router6="2001:db8::1/64",
)
TOPO = nh.Topology(router="snf376_r", endpoints=(LOC,))
_GW6 = "2001:db8::1"  # LOC's IPv6 gateway (router6 host part); the firewall host over IPv6
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="loc", members=(ZoneMember(interface="v_loc", family=Family.BOTH),)),
)
# A family-agnostic admin rule admitting the client to the firewall host (input chain, unguarded so
# it would match both families): the base IPv6 drop is the only thing that keeps v6 out.
_ADMIN = (Rule(action="ACCEPT", source="loc", dest="fw", family=Family.BOTH),)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _ruleset(*, disable_ipv6: bool) -> Ruleset:
    return Ruleset(
        zones=_ZONES, stopped_rules=_ADMIN, settings=Settings(disable_ipv6=disable_ipv6)
    )


@pytest.mark.netns
@_requires_netns
def test_stopped_disable_ipv6_passes_ipv4_and_drops_all_ipv6() -> None:
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(_ruleset(disable_ipv6=True), generator=generate_stopped)
        # IPv4 admin traffic reaches the host; every IPv6 packet is dropped by the base drop.
        assert sb.ping(LOC.name, LOC.gateway4, family=4) is True
        assert sb.ping(LOC.name, _GW6, family=6) is False


@pytest.mark.netns
@_requires_netns
def test_stopped_without_the_gate_both_families_pass() -> None:
    # Control: the same stopped ruleset with DISABLE_IPV6 off admits both families — proving the
    # base drop, not the topology, is what blocks IPv6 above.
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(_ruleset(disable_ipv6=False), generator=generate_stopped)
        assert sb.ping(LOC.name, LOC.gateway4, family=4) is True
        assert sb.ping(LOC.name, _GW6, family=6) is True
