"""Netns behavioral proof of ``+setname`` named-set membership matching (#420, epic #401, ADR-0066).

The compiled path (model #417, parse #418, generator emit #419) lowers a ``+setname`` SOURCE to a
``{ip|ip6} saddr @setname`` membership match (``!=`` when negated) and emits one **empty** nft set
object per referenced set — runtime population is out of scope here (epic #402). This drives the
lowered *lookup rule* on a real packet path: the test itself toggles the set's contents out of band
with ``nft add/delete element`` through :meth:`NetnsSandbox.exec`, so a member and a non-member take
observably different verdicts.

Topology: a dual-stack client wired to the firewall host (the router namespace) — RFC 5737 IPv4 +
RFC 3849 IPv6. The baseline policy is a fail-closed ``client → fw`` DROP, so a packet only reaches
the host when the set-membership rule accepts it; the ping to the firewall host itself exercises the
``input`` chain the rule lands in.

Signals (each contrast is the proof — membership decides the verdict, not the topology):
  * an ``ACCEPT +members`` rule passes the ping only while the source is *in* the set; with the set
    empty the same ping falls to the DROP policy — proving the rule matches on membership;
  * the negated ``ACCEPT !+members`` variant inverts that — a member drops, a non-member passes;
  * family correctness — a ``Family.IPV4`` set populated with the client's v4 address admits the v4
    ping but never the v6 ping (an IPv4 set cannot match a v6 packet), so the v6 flow follows the
    DROP policy on the same dual-stack link.

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 / RFC 3849 documentation ranges only.
"""

from __future__ import annotations

import pytest

from shorewallnf.ir import (
    Family,
    Policy,
    Rule,
    Ruleset,
    SetDef,
    SetRef,
    SetType,
    Zone,
    ZoneMember,
)
from tests import netns_harness as nh

# A dual-stack client wired to the firewall host (the router namespace); unique names so the sandbox
# cannot collide with other netns tests.
_CLIENT = nh.Endpoint(
    name="snf420_c",
    iface="v_cli",
    peer="p_cli",
    addr4="192.0.2.2/24",
    router4="192.0.2.1/24",
    addr6="2001:db8::2/64",
    router6="2001:db8::1/64",
)
_TOPO = nh.Topology(router="snf420_r", endpoints=(_CLIENT,))

# The firewall host's own addresses the client pings (its gateway on each family; the v6 literal
# is the ``router6`` host part, matching the endpoint above).
_ROUTER_V4 = _CLIENT.gateway4
_ROUTER_V6 = "2001:db8::1"

_SET = "members"  # the compiler-emitted, initially-empty ipv4_addr set (inet filter members)

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="client", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _ruleset(*, negated: bool = False) -> Ruleset:
    """A fail-closed ``client → fw`` DROP baseline plus an ``ACCEPT`` rule gated on ``+members``
    (``!+members`` when ``negated``). The set is declared ``Family.IPV4`` so the generator emits a
    single empty ``ipv4_addr`` object named ``members`` and a ``ip saddr @members`` input rule."""
    return Ruleset(
        zones=_ZONES,
        rules=(
            Rule(
                action="ACCEPT",
                source=SetRef(name=_SET, negated=negated, family=Family.IPV4),
                dest="fw",
                family=Family.IPV4,
            ),
        ),
        policies=(Policy(source="client", dest="fw", action="DROP"),),
        sets={_SET: SetDef(name=_SET, family=Family.IPV4, set_type=SetType.ADDRESS)},
    )


def _set_member(sb: nh.NetnsSandbox, verb: str, addr: str) -> None:
    """Toggle ``addr`` in the router's ``inet filter members`` set out of band — the compiler emits
    the set empty (population is epic #402), so the test drives membership itself (``verb`` is
    ``add`` or ``delete``)."""
    sb.exec(_TOPO.router, [nh.NFT, verb, "element", "inet", "filter", _SET, "{", addr, "}"])


@pytest.mark.netns
@_requires_netns
def test_membership_toggles_accept_and_drop() -> None:
    """With the source in the set the ping passes; with the set empty the same ping drops."""
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(_ruleset())
        # Empty set: the source is not a member, so the ACCEPT never fires and the ping falls to the
        # fail-closed DROP policy.
        assert sb.ping(_CLIENT.name, _ROUTER_V4) is False
        # Add the source address: the ACCEPT rule now matches and admits the ping.
        _set_member(sb, "add", _CLIENT.host_ip4)
        assert sb.ping(_CLIENT.name, _ROUTER_V4) is True
        # Remove it again (empty set): the same ping drops — proving the rule matches on membership,
        # not on the topology.
        _set_member(sb, "delete", _CLIENT.host_ip4)
        assert sb.ping(_CLIENT.name, _ROUTER_V4) is False


@pytest.mark.netns
@_requires_netns
def test_negated_membership_inverts_the_verdict() -> None:
    """``!+members`` flips it: a non-member (empty set) passes, a member drops."""
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(_ruleset(negated=True))
        # Empty set: the source is not in the set, so `saddr != @members` is true and the ping is
        # accepted.
        assert sb.ping(_CLIENT.name, _ROUTER_V4) is True
        # Add the source address: it is now a member, so the negated match is false, the ACCEPT is
        # skipped, and the ping falls to the DROP policy.
        _set_member(sb, "add", _CLIENT.host_ip4)
        assert sb.ping(_CLIENT.name, _ROUTER_V4) is False


@pytest.mark.netns
@_requires_netns
def test_ipv4_set_does_not_match_the_v6_flow() -> None:
    """A ``Family.IPV4`` set populated with the client's v4 address admits the v4 ping but leaves
    the v6 ping to follow the DROP policy — an IPv4 set cannot match a v6 packet (family
    correctness)."""
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(_ruleset())
        _set_member(sb, "add", _CLIENT.host_ip4)
        # The v4 packet's source is in the v4 set: the ACCEPT rule admits it.
        assert sb.ping(_CLIENT.name, _ROUTER_V4, family=4) is True
        # The v6 packet cannot match the ipv4_addr set, so no rule accepts it and it follows the
        # fail-closed DROP policy — the v4 membership does not leak across families.
        assert sb.ping(_CLIENT.name, _ROUTER_V6, family=6) is False
