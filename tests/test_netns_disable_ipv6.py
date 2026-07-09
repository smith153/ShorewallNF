"""Netns behavioral proof of the DISABLE_IPV6 family-gate (#369, epic #311, ADR-0061/ADR-0002).

With ``DISABLE_IPV6=Yes`` the generator emits an effectively IPv4-only ``inet`` ruleset: no IPv6
feature rules plus a base ``meta nfproto ipv6 drop`` at the head of every base chain. This drives
real ICMP probes at the firewall host (the router namespace) over a dual-stack endpoint to prove
the observable effect: with the gate on, configured IPv4 traffic still reaches the host while all
IPv6 is dropped; with the gate off (today's dual-stack) both families pass — so the family-gate is
what blocks IPv6. Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier
and runs in the privileged netns CI tier (epics #77/#78).
"""

from __future__ import annotations

import pytest

from shorewallnf.ir import Family, Policy, Ruleset, Settings, Zone, ZoneMember
from tests import netns_harness as nh

# A dual-stack client wired to the firewall host (the router namespace): RFC 5737 IPv4 + RFC 3849
# IPv6 documentation ranges, unique names so the sandbox cannot collide with other netns tests.
LOC = nh.Endpoint(
    name="snf369_loc",
    iface="v_loc",
    peer="p_loc",
    addr4="192.0.2.2/24",
    router4="192.0.2.1/24",
    addr6="2001:db8::2/64",
    router6="2001:db8::1/64",
)
TOPO = nh.Topology(router="snf369_r", endpoints=(LOC,))
_GW6 = "2001:db8::1"  # LOC's IPv6 gateway (router6 host part); the firewall host over IPv6
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="loc", members=(ZoneMember(interface="v_loc", family=Family.BOTH),)),
)
# A family-agnostic policy admitting the client to the firewall host (input chain, unguarded so it
# would match both families): the base IPv6 drop is the only thing that keeps v6 out.
_POLICY = (Policy(source="loc", dest="fw", action="ACCEPT"),)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _ruleset(*, disable_ipv6: bool) -> Ruleset:
    return Ruleset(zones=_ZONES, policies=_POLICY, settings=Settings(disable_ipv6=disable_ipv6))


@pytest.mark.netns
@_requires_netns
def test_disable_ipv6_passes_ipv4_and_drops_all_ipv6() -> None:
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(_ruleset(disable_ipv6=True))
        # IPv4 reaches the host as configured; every IPv6 packet is dropped by the base drop.
        assert sb.ping(LOC.name, LOC.gateway4, family=4) is True
        assert sb.ping(LOC.name, _GW6, family=6) is False


@pytest.mark.netns
@_requires_netns
def test_without_the_gate_both_families_pass() -> None:
    # Control: the same config with DISABLE_IPV6 off admits both families — proving the gate, not
    # the topology, is what blocks IPv6 above.
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(_ruleset(disable_ipv6=False))
        assert sb.ping(LOC.name, LOC.gateway4, family=4) is True
        assert sb.ping(LOC.name, _GW6, family=6) is True
