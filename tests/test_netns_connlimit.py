"""Netns behavioral proof of the rules CONNLIMIT column (#407, epic #400, ADR-0007).

Drives that an nft ``ct count over N`` emitted before a rule's verdict actually caps the number of
*simultaneous* connections on the wire: while fewer than the cap are open a new connection is
admitted, and once the cap is reached a further new connection takes the CONNLIMIT rule's verdict.

Rule polarity (faithful to Shorewall, ADR-0007): CONNLIMIT ``N`` compiles to ``ct count over N``,
which — per nft/conntrack semantics — *continues to the rule's verdict* when the live connection
count is over ``N`` and falls through otherwise. So a ``DROP`` rule carrying CONNLIMIT ``N`` in
front of an ``ACCEPT`` policy is the natural limiter: the first ``N`` simultaneous connections fall
through the DROP rule and are accepted by the policy, and the (N+1)th onward push the count over
``N`` and are dropped. That inverse — accept below the cap, drop at/over it — is exactly "stops
accepting once the concurrent-connection cap is reached".

Why the connections must be **distinct and concurrently open** (the #406 lesson, sharpened for a
*connection* count): ``ct count`` counts entries live in conntrack, not packets. A single long flow
is one conntrack entry and never exceeds a cap above 1; and connections opened and *closed*
serially are never simultaneously live, so they never stack up against the cap. This test therefore
opens many separate TCP connections **and holds every socket open** for the duration of the
measurement, so they are all live in conntrack at once and genuinely stack against the cap. The
bare (ungrouped) CONNLIMIT is a per-rule *global* cap (the per-source masked form is #416), so a
single client suffices — the distinctness that matters is one conntrack entry per held connection.

Topology: a router namespace between a client and a server, each on its own RFC 5737 subnet. The
client opens TCP connections to a held-open listener on the server through the router; the router's
``forward`` chain caps them.

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 documentation ranges only.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from shorewallnf.ir import (
    ConnLimit,
    Family,
    Policy,
    Rule,
    Ruleset,
    Zone,
    ZoneMember,
)
from tests import netns_harness as nh

_CLIENT = nh.Endpoint(
    name="snf407_c", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_SERVER = nh.Endpoint(
    name="snf407_s", iface="v_srv", peer="p_srv", addr4="198.51.100.2/24", router4="198.51.100.1/24"
)
_TOPO = nh.Topology(router="snf407_r", endpoints=(_CLIENT, _SERVER))

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="cli", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
    Zone(name="srv", members=(ZoneMember(interface="v_srv", family=Family.BOTH),)),
)

_PORT = 9407
# Cap the client->server TCP connections at _CAP simultaneous; connections over the cap take the
# DROP verdict, the rest fall through to the ACCEPT policy. Scoped IPv4 so the both-family split
# doesn't double the ct-count statement.
_CAP = 4
_RULES = (
    Rule(
        action="DROP", source="cli", dest="srv", proto="tcp", dport=str(_PORT),
        connlimit=ConnLimit(count=_CAP), family=Family.IPV4,
    ),
)
_POLICIES = (Policy(source="cli", dest="srv", action="ACCEPT"),)

# How many connections beyond the cap the second phase tries. All should be blocked (the _CAP from
# phase one are still held open, so each of these pushes the live count over _CAP); the ceiling
# leaves slack for conntrack accounting so the assertion proves capping without going flaky.
_EXTRA = 8

# A held-open accept loop: accept every connection and keep it open (never close) so each stays live
# in conntrack for the whole measurement. Backlog covers the full _CAP+_EXTRA burst.
_HOLD_LISTEN = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.bind(('0.0.0.0', int(sys.argv[1])))\n"
    "s.listen(64)\n"
    "held=[]\n"
    "while True:\n"
    "    try:\n"
    "        c,_=s.accept()\n"
    "        held.append(c)\n"
    "    except OSError:\n"
    "        break\n"
)

# Open `first` then `second` TCP connections to host:port, holding every successful socket open, and
# print "<opened_in_first> <opened_in_second>". Because the phase-one sockets stay open, the
# phase-two attempts see the cap already full.
_HOLD_CONNECT = (
    "import socket,sys\n"
    "host=sys.argv[1]; port=int(sys.argv[2])\n"
    "first=int(sys.argv[3]); second=int(sys.argv[4]); timeout=float(sys.argv[5])\n"
    "held=[]\n"
    "def one():\n"
    "    s=socket.socket(); s.settimeout(timeout)\n"
    "    try:\n"
    "        s.connect((host,port)); held.append(s); return 1\n"
    "    except OSError:\n"
    "        s.close(); return 0\n"
    "a=sum(one() for _ in range(first))\n"
    "b=sum(one() for _ in range(second))\n"
    "print(a, b)\n"
)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _await_listener(sb: nh.NetnsSandbox, ns: str, port: int, *, attempts: int = 50) -> None:
    """Block until the held-open listener in ``ns`` is accepting. The probe is a loopback connect
    inside ``ns`` (127.0.0.1), which never traverses the router/firewall — so it confirms the bind
    without consuming a slot against the client->server CONNLIMIT cap."""
    for _ in range(attempts):
        if sb.connect(ns, "127.0.0.1", port, timeout=0.2) == "open":
            return
        time.sleep(0.1)
    raise RuntimeError(f"listener on {ns}:{port} never came up")


@pytest.mark.netns
@_requires_netns
def test_connlimit_caps_simultaneous_connections() -> None:
    rs = Ruleset(zones=_ZONES, rules=_RULES, policies=_POLICIES)
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(rs)
        listener = subprocess.Popen(
            [nh.IP, "netns", "exec", _SERVER.name, nh.PY3, "-c", _HOLD_LISTEN, str(_PORT)]
        )
        try:
            _await_listener(sb, _SERVER.name, _PORT)
            out = sb.exec(
                _CLIENT.name,
                [
                    nh.PY3, "-c", _HOLD_CONNECT, _SERVER.host_ip4, str(_PORT),
                    str(_CAP), str(_EXTRA), "1.0",
                ],
                check=False,
            ).stdout
        finally:
            listener.terminate()
            listener.wait()
    below, over = (int(x) for x in out.split())
    # Below the cap every distinct simultaneous connection is admitted (they fall through the DROP
    # rule to the ACCEPT policy) — proving the rule does not blanket-block.
    assert below == _CAP
    # With the cap already full of held-open connections, connections over it are dropped — only a
    # handful at most slip through, proving the ct count caps simultaneous connections rather than
    # admitting everything.
    assert over <= _EXTRA // 2
