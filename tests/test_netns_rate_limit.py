"""Netns behavioral proof of the rules RATE LIMIT column (#406, epic #400, ADR-0007).

Drives that an nft ``limit rate`` emitted before a rule's verdict actually throttles traffic on
the wire: *new connections* under the configured rate take the ACCEPT verdict, new connections
over it fall through to the fail-closed ``forward`` policy (DROP).

Why distinct flows, not one long ping: Shorewall RATE LIMIT rate-limits *new connections* matching
the rule (ADR-0007), and the generator slots the ``limit rate`` after the base
established/related accept (ADR-0005, ``generator.py`` forward chain). So only the **first** packet
of a conntrack flow is NEW and ever reaches the limiter; a single ``ping -c N`` is one ICMP flow
(one id), whose packets 2..N are ESTABLISHED and are admitted by the base-accept *ahead* of the
limit rule — they never touch it. To exercise the limiter we therefore fire many **separate**
``ping -c1`` processes: each is its own process with its own ICMP echo id, hence a distinct
conntrack flow whose sole packet is NEW and must pass the limiter to get through.

Topology: a router namespace between a client and a server, each on its own RFC 5737 subnet. The
client pings the server through the router; the router's ``forward`` chain rate-limits the ACCEPT.

Signals (same rule, opposite rates — the contrast is the proof, not either half alone):
  * a slow, under-rate sequence of distinct new flows gets every probe through — the rule admits
    below-limit new connections;
  * a fast burst of many distinct new flows, far above the rate, loses the excess — only a handful
    (~burst) get through, proving the limiter drops over-rate *new* connections rather than a
    blanket drop (some pass) or a tautological pass-all (most are dropped).

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 documentation ranges only.
"""

from __future__ import annotations

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

# ACCEPT client->server ICMP at a low rate; every new connection over the limit falls through to
# the DROP policy. A small burst keeps the under-rate case deterministic while the over-rate burst
# still swamps it. Scoped IPv4 so the both-family split doesn't double the limiter.
_RATE = RateLimit(rate=2, interval="second", burst=2)
_RULES = (
    Rule(action="ACCEPT", source="cli", dest="srv", proto="icmp", rate=_RATE, family=Family.IPV4),
)
_POLICIES = (Policy(source="cli", dest="srv", action="DROP"),)

# Over-rate burst size. Fired concurrently against a 2/second (burst 2) limiter, only ~burst get
# through; the ceiling below leaves generous headroom for token refill during process spawn so the
# assertion proves throttling without going flaky.
_BURST = 30

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _spaced_new_flows(sb: nh.NetnsSandbox, count: int, interval: float) -> int:
    """Fire ``count`` distinct NEW ICMP flows one at a time, ``interval`` seconds apart, and return
    how many drew a reply.

    Each ``ping -c1`` is a separate process with its own ICMP echo id, so every probe is a fresh
    conntrack flow whose sole packet is NEW and must clear the ``limit rate`` to get through — none
    ride an ESTABLISHED entry past the base-accept the way one long ``ping -cN`` flow would.
    """
    script = (
        f"n=0; i=0; "
        f'while [ "$i" -lt {count} ]; do '
        f"i=$((i+1)); "
        f"ping -4 -c1 -W1 {_SERVER.host_ip4} >/dev/null 2>&1 && n=$((n+1)); "
        f'[ "$i" -lt {count} ] && sleep {interval}; '
        f'done; echo "$n"'
    )
    return _count(sb.exec(_CLIENT.name, ["sh", "-c", script], check=False).stdout)


def _burst_new_flows(sb: nh.NetnsSandbox, count: int) -> int:
    """Fire ``count`` distinct NEW ICMP flows *concurrently* and return how many drew a reply.

    The pings are backgrounded so all ``count`` echo requests egress within a few milliseconds of
    each other — a genuine burst of distinct NEW flows hitting the limiter near-simultaneously, so
    only ~burst clear it and the rest fall through to the DROP policy.
    """
    script = (
        f"pids=; "
        f"for i in $(seq {count}); do "
        f"ping -4 -c1 -W1 {_SERVER.host_ip4} >/dev/null 2>&1 & pids=\"$pids $!\"; "
        f"done; "
        f'n=0; for p in $pids; do wait "$p" && n=$((n+1)); done; echo "$n"'
    )
    return _count(sb.exec(_CLIENT.name, ["sh", "-c", script], check=False).stdout)


def _count(stdout: str) -> int:
    """Parse the trailing success count the probe scripts echo."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    return int(lines[-1]) if lines else 0


@pytest.mark.netns
@_requires_netns
def test_rate_limit_throttles_above_rate_and_passes_below() -> None:
    rs = Ruleset(zones=_ZONES, rules=_RULES, policies=_POLICIES)
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(rs)
        # Under-rate: three distinct new flows a second apart are all admitted (the 2/second bucket
        # keeps up), proving the limiter passes below-limit new connections.
        assert _spaced_new_flows(sb, count=3, interval=1.0) == 3
        # Over-rate: a concurrent burst of distinct new flows far above the rate is throttled — a
        # handful (~burst) get through, but far from all, proving the limiter drops the excess new
        # connections rather than admitting everything or dropping everything.
        received = _burst_new_flows(sb, count=_BURST)
        assert 1 <= received <= _BURST // 2
