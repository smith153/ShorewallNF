"""Netns behavioral proof of the stopped safe state (#213, epic #201, ADR-0021).

``stop`` loads a fail-closed ruleset admitting only declared admin-access traffic (stoppedrules)
plus the no-lockout baseline (loopback + established/related). This drives real TCP probes at the
firewall host (the router namespace) to prove: a packet matching a declared admin rule reaches the
host, a non-admin packet is dropped, and with zero admin rules the baseline still admits loopback
while dropping new non-admin traffic. The stopped ruleset loads through the harness ``generator``
seam (:func:`shorewallnf.generator.generate_stopped`). Gated on the ``netns`` marker + root, so it
skips cleanly in the hermetic tier and runs in the privileged netns CI tier (epics #77/#78).
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import pytest

from shorewallnf.generator import generate_stopped
from shorewallnf.ir import Family, Rule, Ruleset, Zone, ZoneMember
from tests import netns_harness as nh

# An admin client wired to the firewall host (the router namespace); RFC 5737 range, unique names
# so the sandbox cannot collide with other netns tests.
ADMIN = nh.Endpoint(
    name="snf213_admin", iface="v_adm", peer="p_adm", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
TOPO = nh.Topology(router="snf213_r", endpoints=(ADMIN,))
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="admin", members=(ZoneMember(interface="v_adm", family=Family.BOTH),)),
)
_ADMIN_PORT = 22  # a declared admin rule opens this on the host
_BLOCKED_PORT = 8080  # no rule opens this — the fail-closed input policy must drop it

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)

# One-shot TCP connect run inside a namespace: prints host:port reachability. A refused (RST) is
# distinguished from a timeout (SYN silently dropped) so a firewalled port reads as ``filtered``.
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

# A trivial accept-and-close TCP listener bound to every interface.
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
    """Run a TCP listener per port in ``ns``, waiting until each accepts before yielding so a probe
    can never race the bind."""
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
    """Block until a loopback connect inside ``ns`` reaches the listener (loopback is admitted by
    the no-lockout baseline, so this confirms the bind, not the firewall)."""
    for _ in range(attempts):
        if _connect(sb, ns, "127.0.0.1", port, timeout=0.2) == "open":
            return
        time.sleep(0.1)
    raise RuntimeError(f"listener on {ns}:{port} never came up")


def _stopped(*rules: Rule) -> Ruleset:
    return Ruleset(zones=_ZONES, stopped_rules=rules)


@pytest.mark.netns
@_requires_netns
def test_stopped_state_admits_admin_and_drops_the_rest() -> None:
    # A declared admin rule (SSH from the admin zone to the firewall) reaches the host; a port no
    # rule opens is dropped by the fail-closed input policy.
    rs = _stopped(Rule(action="ACCEPT", source="admin", dest="fw", proto="tcp", dport="22"))
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(rs, generator=generate_stopped)
        with _listeners(sb, TOPO.router, (_ADMIN_PORT, _BLOCKED_PORT)):
            assert _connect(sb, ADMIN.name, ADMIN.gateway4, _ADMIN_PORT) == "open"
            assert _connect(sb, ADMIN.name, ADMIN.gateway4, _BLOCKED_PORT) == "filtered"


@pytest.mark.netns
@_requires_netns
def test_stopped_state_without_admin_rules_is_no_lockout_baseline() -> None:
    # Zero admin rules: the baseline still admits loopback on the host, but a new non-admin
    # connection from the client is dropped — no lockout, no open door.
    rs = _stopped()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(rs, generator=generate_stopped)
        with _listeners(sb, TOPO.router, (_ADMIN_PORT,)):
            assert _connect(sb, TOPO.router, "127.0.0.1", _ADMIN_PORT) == "open"
            assert _connect(sb, ADMIN.name, ADMIN.gateway4, _ADMIN_PORT) == "filtered"
