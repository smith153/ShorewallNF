"""Netns behavioral proof of the rpfilter reverse-path check (#380, epic #310, ADR-0063).

An interface carrying ``rpfilter`` gets a prerouting rule ``iifname <if> fib saddr . iif oif
missing`` → disposition (default DROP), placed at ``priority raw`` so a spoofed packet drops
before conntrack and before the ADR-0005 established/related base-accept. This drives that on a
real packet path.

Topology: a firewall host (the router namespace) multi-homed to **one** client namespace by two
links — link A (``v_a`` ⇄ ``p_a``, ``192.0.2.0/24``) and link B (``v_b`` ⇄ ``p_b``,
``198.51.100.0/24``). Multi-homing the *same* client on both subnets is what makes the probe
observable: a packet sent from the client's B-subnet address but out link A reverse-routes (on the
router) back out link B, so with rpfilter off the router's reply still reaches the client and the
ping succeeds — while rpfilter on drops the spoofed ingress outright. The router's kernel
``rp_filter`` sysctl is forced off on both so only the nft rule governs the verdict.

Signals:
  * legit source (owned by the ingress link) always passes — rpfilter never blocks honest traffic;
  * a source that reverse-routes out the *other* link is dropped with rpfilter on;
  * the same spoofed packet passes with rpfilter off — proving the rule, not the topology, blocks;
  * a non-default REJECT disposition still blocks it (the emitted verdict identity is pinned by the
    golden tests).

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 documentation ranges only.
"""

from __future__ import annotations

import pytest

from shorewallnf.ir import (
    Disposition,
    Family,
    Interface,
    Policy,
    Ruleset,
    Settings,
    Zone,
    ZoneMember,
)
from tests import netns_harness as nh

# The client, wired to the firewall host over link A (subnet 192.0.2.0/24). Link B is added by
# hand below so the *same* client namespace is multi-homed onto 198.51.100.0/24 as well.
_CLI = nh.Endpoint(
    name="snf380_c", iface="v_a", peer="p_a", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_TOPO = nh.Topology(router="snf380_r", endpoints=(_CLI,))

# link B temp (root-ns) names, and the router/client device names + addresses it carries.
_LB_TMP_R, _LB_TMP_C = "snf380lb", "snf380lc"
_V_B, _P_B = "v_b", "p_b"
_ROUTER_B, _CLIENT_B = "198.51.100.1/24", "198.51.100.2/24"
_CLIENT_B_ADDR = "198.51.100.2"
_CLIENT_A_ADDR = "192.0.2.2"
_ROUTER_A_ADDR = "192.0.2.1"

# The two interfaces belong to one network zone admitted to the firewall host, so an accepted ping
# reaches ``input``; rpfilter (when set) drops the spoofed one earlier, in prerouting.
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(
        name="loc",
        members=(
            ZoneMember(interface="v_a", family=Family.BOTH),
            ZoneMember(interface=_V_B, family=Family.BOTH),
        ),
    ),
)
_POLICIES = (Policy(source="loc", dest="fw", action="ACCEPT"),)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _ruleset(*, rpfilter: bool, disposition: Disposition = Disposition.DROP) -> Ruleset:
    return Ruleset(
        zones=_ZONES,
        interfaces=(Interface(name="v_a", rpfilter=rpfilter), Interface(name=_V_B)),
        policies=_POLICIES,
        settings=Settings(rpfilter_disposition=disposition),
    )


def _add_link_b() -> None:
    """Add link B between the router and the client, multi-homing the client on 198.51.100.0/24."""
    nh._run([nh.IP, "link", "add", _LB_TMP_R, "type", "veth", "peer", "name", _LB_TMP_C])
    nh._run([nh.IP, "link", "set", _LB_TMP_R, "netns", _TOPO.router])
    nh._run([nh.IP, "link", "set", _LB_TMP_C, "netns", _CLI.name])
    nh._run([nh.IP, "-n", _TOPO.router, "link", "set", _LB_TMP_R, "name", _V_B])
    nh._run([nh.IP, "-n", _CLI.name, "link", "set", _LB_TMP_C, "name", _P_B])
    nh._run([nh.IP, "-n", _TOPO.router, "addr", "add", _ROUTER_B, "dev", _V_B])
    nh._run([nh.IP, "-n", _CLI.name, "addr", "add", _CLIENT_B, "dev", _P_B])
    nh._run([nh.IP, "-n", _TOPO.router, "link", "set", _V_B, "up"])
    nh._run([nh.IP, "-n", _CLI.name, "link", "set", _P_B, "up"])
    # Force the kernel reverse-path sysctl off on both hosts so ONLY the nft rpfilter rule decides
    # the verdict: on the router (else the control below is contaminated) and on the client (so it
    # accepts the router's reply arriving on p_b for a p_b-owned source, i.e. asymmetric return).
    for ns, dev in (
        (_TOPO.router, "all"), (_TOPO.router, "v_a"), (_TOPO.router, _V_B),
        (_CLI.name, "all"), (_CLI.name, "p_a"), (_CLI.name, _P_B),
    ):
        nh._run(
            [nh.IP, "netns", "exec", ns, "sysctl", "-qw", f"net.ipv4.conf.{dev}.rp_filter=0"]
        )


def _ping(src: str, dst: str) -> bool:
    """Ping ``dst`` from the client sourced from ``src`` (forcing an ingress/source mismatch)."""
    result = nh._run(
        [nh.IP, "netns", "exec", _CLI.name, "ping", "-4", "-c", "1", "-W", "1", "-I", src, dst],
        check=False,
    )
    return result.returncode == 0


@pytest.mark.netns
@_requires_netns
def test_rpfilter_drops_spoofed_source_but_passes_legit() -> None:
    with nh.NetnsSandbox(_TOPO) as sb:
        _add_link_b()
        sb.load(_ruleset(rpfilter=True))
        # A source owned by the ingress link (v_a) reverse-routes back out v_a: rpfilter passes it,
        # and the loc→fw policy admits it to the firewall host.
        assert _ping(_CLIENT_A_ADDR, _ROUTER_A_ADDR) is True
        # A source from the B subnet arriving on v_a reverse-routes out v_b (≠ ingress) → rpfilter
        # drops it in prerouting, before it can reach input.
        assert _ping(_CLIENT_B_ADDR, _ROUTER_A_ADDR) is False


@pytest.mark.netns
@_requires_netns
def test_without_rpfilter_the_spoofed_source_passes() -> None:
    # Control: the identical spoofed packet passes when v_a carries no rpfilter — proving the rule,
    # not the routing/topology, is what dropped it above.
    with nh.NetnsSandbox(_TOPO) as sb:
        _add_link_b()
        sb.load(_ruleset(rpfilter=False))
        assert _ping(_CLIENT_B_ADDR, _ROUTER_A_ADDR) is True


@pytest.mark.netns
@_requires_netns
def test_reject_disposition_still_blocks_the_spoofed_source() -> None:
    # A non-default disposition still terminates the spoofed packet (the emitted verdict changes to
    # `reject`, pinned byte-for-byte by the golden tests); the ping stays blocked.
    with nh.NetnsSandbox(_TOPO) as sb:
        _add_link_b()
        sb.load(_ruleset(rpfilter=True, disposition=Disposition.REJECT))
        assert _ping(_CLIENT_B_ADDR, _ROUTER_A_ADDR) is False
