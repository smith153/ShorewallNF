"""Netns behavioral coverage for a built-in macro and a site-defined action (task #185, epic #176).

Proves the macro/action resolver (ADR-0020) makes the intended packets flow on the wire: a config
invoking the built-in ``Web`` macro and one invoking a site-defined ``action.<Name>`` each compile,
load into the router namespace, and open **exactly** the ports the macro/action names — while the
fail-closed ``forward`` policy drops everything else. The scoped macros are TCP/UDP port rules, so
this drives real TCP probes through the harness ``.exec()`` (ICMP ``ping`` never reaches a port
rule). Every probed port carries a live listener, so the only thing separating an ``open`` result
from a ``filtered`` (timed-out) one is the firewall: if the macro/action stopped expanding, the
allowed port would time out; if the fail-closed default regressed to allow-all, the blocked port
would connect. Gated on the ``netns`` marker + :func:`netns_harness.netns_available`, so it skips
cleanly in the hermetic tier and runs in the privileged/netns CI tier (epics #77/#78).
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import pytest

from shorewallnf.ir import Family, MacroDef, MacroRule, Rule, Ruleset, Zone, ZoneMember
from shorewallnf.resolver import resolve
from tests import netns_harness as nh

# A client and a server namespace wired to the router; RFC 5737 documentation ranges (no
# my_shorewall/ values), unique namespace names so the sandbox cannot collide with other tests.
CLIENT = nh.Endpoint(
    name="snf185_client", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
SERVER = nh.Endpoint(
    name="snf185_server", iface="v_srv", peer="p_srv",
    addr4="198.51.100.2/24", router4="198.51.100.1/24",
)
TOPO = nh.Topology(router="snf185_r", endpoints=(CLIENT, SERVER))

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="client", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
    Zone(name="server", members=(ZoneMember(interface="v_srv", family=Family.BOTH),)),
)

# A site-defined ``action.AllowSsh`` (as the parser would populate ``Ruleset.actions``): accept
# TCP on a single custom port. Distinct from any built-in port so the two tests can't alias.
_ACTIONS = {
    "AllowSsh": MacroDef(
        name="AllowSsh", body=(MacroRule(action="ACCEPT", proto="tcp", dport="2222"),)
    )
}

# A port no rule ever opens: the fail-closed forward policy must drop it (asserted as ``filtered``).
_BLOCKED_PORT = 8080

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)

# One-shot TCP connect run inside a namespace: prints the reachability of ``host:port``.
# ``ConnectionRefusedError`` (RST) is distinguished from any other ``OSError`` (a timeout means
# the SYN was silently dropped) so a blocked port reads as ``filtered``, not ``refused``.
_CONNECT = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.settimeout(float(sys.argv[3]))\n"
    "try:\n"
    "    s.connect((sys.argv[1], int(sys.argv[2])))\n"
    "    print('open')\n"
    "except ConnectionRefusedError:\n"
    "    print('refused')\n"
    "except OSError:\n"
    "    print('filtered')\n"
)

# A trivial accept-and-close TCP listener bound to every interface, run in the server namespace.
_LISTEN = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.bind(('0.0.0.0', int(sys.argv[1])))\n"
    "s.listen(16)\n"
    "while True:\n"
    "    try:\n"
    "        c, _ = s.accept()\n"
    "        c.close()\n"
    "    except OSError:\n"
    "        break\n"
)


def _connect(
    sb: nh.NetnsSandbox, src_ns: str, host: str, port: int, *, timeout: float = 1.0
) -> str:
    """Probe ``host:port`` from ``src_ns``: ``open`` / ``refused`` / ``filtered`` (timed out)."""
    result = sb.exec(
        src_ns, ["python3", "-c", _CONNECT, host, str(port), str(timeout)], check=False
    )
    return result.stdout.strip()


@contextmanager
def _listeners(sb: nh.NetnsSandbox, ns: str, ports: Sequence[int]) -> Iterator[None]:
    """Run a TCP listener per port in ``ns`` for the duration of the block, waiting until each is
    accepting before yielding so a probe can never race the bind."""
    procs = [
        subprocess.Popen(["ip", "netns", "exec", ns, "python3", "-c", _LISTEN, str(port)])
        for port in ports
    ]
    try:
        for port in ports:
            _await_listener(sb, ns, port)
        yield
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            proc.wait()


def _await_listener(sb: nh.NetnsSandbox, ns: str, port: int, *, attempts: int = 50) -> None:
    """Block until a loopback connect inside ``ns`` reaches the listener (bind is not filtered)."""
    for _ in range(attempts):
        if _connect(sb, ns, "127.0.0.1", port, timeout=0.2) == "open":
            return
        time.sleep(0.1)
    raise RuntimeError(f"listener on {ns}:{port} never came up")


@pytest.mark.netns
@_requires_netns
def test_builtin_macro_opens_its_ports() -> None:
    """The ``Web`` macro (TCP 80/443) admits those ports client→server; 8080 stays dropped."""
    ruleset = resolve(
        Ruleset(zones=_ZONES, rules=(Rule(action="Web", source="client", dest="server"),))
    )
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        with _listeners(sb, SERVER.name, (80, 443, _BLOCKED_PORT)):
            assert _connect(sb, CLIENT.name, SERVER.host_ip4, 80) == "open"
            assert _connect(sb, CLIENT.name, SERVER.host_ip4, 443) == "open"
            assert _connect(sb, CLIENT.name, SERVER.host_ip4, _BLOCKED_PORT) == "filtered"


@pytest.mark.netns
@_requires_netns
def test_site_action_opens_its_port() -> None:
    """A site-defined ``action.AllowSsh`` (TCP 2222) admits its port; 8080 stays dropped."""
    ruleset = resolve(
        Ruleset(
            zones=_ZONES,
            rules=(Rule(action="AllowSsh", source="client", dest="server"),),
            actions=_ACTIONS,
        )
    )
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        with _listeners(sb, SERVER.name, (2222, _BLOCKED_PORT)):
            assert _connect(sb, CLIENT.name, SERVER.host_ip4, 2222) == "open"
            assert _connect(sb, CLIENT.name, SERVER.host_ip4, _BLOCKED_PORT) == "filtered"
