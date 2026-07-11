"""Netns behavioral proof of the rules RATE LIMIT column (#406, epic #400, ADR-0007).

Drives that an nft ``limit rate`` emitted before a rule's verdict actually throttles traffic on
the wire: packets under the configured rate take the ACCEPT verdict, packets over it fall through
to the fail-closed ``forward`` policy (DROP). ICMP echo is the clean observable — one request is
one packet, so counting echo replies counts admitted packets — the rule is scoped to a low rate.

Topology: a router namespace between a client and a server, each on its own RFC 5737 subnet. The
client pings the server through the router; the router's ``forward`` chain rate-limits the ACCEPT.

Signals:
  * a slow, under-rate sequence gets every ping through (the rule admits below-limit traffic);
  * a fast burst well above the rate loses packets (the limiter throttles above-limit traffic),
    while still admitting at least the burst — proving the limiter, not a blanket drop, is at work.

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 documentation ranges only.
"""

from __future__ import annotations

import re

import pytest

from shorewallnf.ir import (
    Family,
    Policy,
    RateLimit,
    Rule,
    Ruleset,
    Zone,
    ZoneMember,
)
from tests import netns_harness as nh

_CLIENT = nh.Endpoint(
    name="snf406_c", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_SERVER = nh.Endpoint(
    name="snf406_s", iface="v_srv", peer="p_srv", addr4="198.51.100.2/24", router4="198.51.100.1/24"
)
_TOPO = nh.Topology(router="snf406_r", endpoints=(_CLIENT, _SERVER))

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="cli", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
    Zone(name="srv", members=(ZoneMember(interface="v_srv", family=Family.BOTH),)),
)

# ACCEPT client→server ICMP at a low rate; everything over the limit falls through to the DROP
# policy. A generous burst keeps the under-rate case deterministic; the over-rate burst still
# swamps it. Scoped IPv4 so the both-family split doesn't double the limiter.
_RATE = RateLimit(rate=2, interval="second", burst=2)
_RULES = (
    Rule(action="ACCEPT", source="cli", dest="srv", proto="icmp", rate=_RATE, family=Family.IPV4),
)
_POLICIES = (Policy(source="cli", dest="srv", action="DROP"),)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _ping_received(sb: nh.NetnsSandbox, count: int, interval: float) -> int:
    """Send ``count`` pings client→server at ``interval`` seconds apart; return replies received."""
    result = sb.exec(
        _CLIENT.name,
        ["ping", "-4", "-c", str(count), "-i", str(interval), "-W", "1", _SERVER.host_ip4],
        check=False,
    )
    match = re.search(r"(\d+) received", result.stdout)
    return int(match.group(1)) if match else 0


@pytest.mark.netns
@_requires_netns
def test_rate_limit_throttles_above_rate_and_passes_below() -> None:
    rs = Ruleset(zones=_ZONES, rules=_RULES, policies=_POLICIES)
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(rs)
        # Under-rate: three pings a second apart are all admitted (2/sec bucket keeps up).
        assert _ping_received(sb, count=3, interval=1.0) == 3
        # Over-rate: a 20-packet burst is throttled — some get through (at least the burst), but
        # far from all, proving the limiter drops the excess rather than everything.
        received = _ping_received(sb, count=20, interval=0.05)
        assert 1 <= received < 20
