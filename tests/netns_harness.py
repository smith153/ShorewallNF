"""Behavioral (netns) test harness (task #115, epic #77).

The behavioral tier that complements the hermetic golden-file harness
(:mod:`tests.golden_harness`): it builds a throwaway ``ip netns`` sandbox — a router
namespace wired by veth pairs to one or more endpoint namespaces — loads a generated
nftables ruleset into the router, and drives real traffic between endpoints to assert a
packet-path behavior (e.g. a policy ``DROP`` blocks a ping).

Design (ADR-0003, functional core / imperative shell):

- **Pure core** — :class:`Topology`/:class:`Endpoint` describe a sandbox, and the
  ``*_commands`` planners turn one into the exact ``ip``/``nft`` argv lists. These are
  hermetic and unit-tested without root.
- **Imperative shell** — :class:`NetnsSandbox` just runs those commands via ``subprocess``.
  It needs root and the ``ip``/``nft`` binaries, so callers gate on :func:`netns_available`.

Rendering reuses the generator (:func:`shorewallnf.generator.generate`) — the same IR -> JSON
seam the golden-file harness checks — rather than re-implementing it.

Requirements: run as **root** on Linux with iproute2 (``ip``) and nftables (``nft``) installed.
Where any of those is absent, :func:`netns_available` is false and behavioral tests skip cleanly,
keeping the hermetic tier green without privileges. Wiring a CI job that *has* those is epic #78.

Writing a behavioral test::

    from tests import netns_harness as nh

    ZONES = (Zone("fw", is_firewall=True),
             Zone("client", members=(ZoneMember("v_cli", Family.BOTH),)),
             Zone("server", members=(ZoneMember("v_srv", Family.BOTH),)))
    CLIENT = nh.Endpoint("client", "v_cli", "p_cli", "192.0.2.2/24", "192.0.2.1/24")
    SERVER = nh.Endpoint("server", "v_srv", "p_srv", "198.51.100.2/24", "198.51.100.1/24")
    TOPO = nh.Topology("router", (CLIENT, SERVER))

    @pytest.mark.skipif(not nh.netns_available(), reason="needs root + ip/nft")
    def test_something() -> None:
        rs = Ruleset(zones=ZONES, policies=(Policy("client", "server", "DROP"),))
        with nh.NetnsSandbox(TOPO) as sb:   # builds and (on exit) tears the sandbox down
            sb.load(rs)                      # flush + load the generated ruleset into the router
            assert not sb.ping("client", SERVER.host_ip4)

A zone's ``ZoneMember.interface`` must name the **router-side** veth of the endpoint
(``Endpoint.iface``) so the generated ``iifname``/``oifname`` matches line up with the sandbox.
Endpoints carry optional ``addr6``/``router6`` for dual-stack ICMP; DNAT/SNAT tests use
:meth:`NetnsSandbox.exec` to run an arbitrary client (e.g. a socket probe) inside a namespace.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from shorewallnf.generator import generate
from shorewallnf.ir import Ruleset

IP = "ip"
NFT = "nft"


# ---- availability -----------------------------------------------------------------------


def netns_available() -> bool:
    """True when a netns sandbox can be built: running as root with ``ip`` and ``nft`` present."""
    return _is_root() and _have_binaries((IP, NFT))


def _is_root() -> bool:
    return os.geteuid() == 0


def _have_binaries(names: Sequence[str]) -> bool:
    return all(shutil.which(name) is not None for name in names)


# ---- topology model (pure) --------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    """A host namespace attached to the router by one veth pair.

    ``iface`` is the router-side veth (name it as the zone's interface in the ruleset);
    ``peer`` is the host-side veth. ``addr4``/``router4`` are the host- and router-side
    IPv4 ``address/prefix`` strings; ``addr6``/``router6`` add an optional IPv6 pair.
    """

    name: str
    iface: str
    peer: str
    addr4: str
    router4: str
    addr6: str | None = None
    router6: str | None = None

    @property
    def host_ip4(self) -> str:
        return self.addr4.split("/", 1)[0]

    @property
    def gateway4(self) -> str:
        return self.router4.split("/", 1)[0]

    @property
    def host_ip6(self) -> str | None:
        return self.addr6.split("/", 1)[0] if self.addr6 else None

    @property
    def gateway6(self) -> str | None:
        return self.router6.split("/", 1)[0] if self.router6 else None


@dataclass(frozen=True)
class Topology:
    """A router namespace and the endpoint namespaces attached to it."""

    router: str
    endpoints: tuple[Endpoint, ...]

    @property
    def namespaces(self) -> tuple[str, ...]:
        return (self.router, *(e.name for e in self.endpoints))


# ---- command planning (pure) ------------------------------------------------------------


def setup_commands(topo: Topology) -> list[list[str]]:
    """The ``ip`` argv sequence that builds ``topo``: namespaces, veth pairs, addresses,
    endpoint default routes, and router forwarding."""
    cmds: list[list[str]] = [[IP, "netns", "add", ns] for ns in topo.namespaces]
    cmds.append([IP, "-n", topo.router, "link", "set", "lo", "up"])
    cmds.append([IP, "netns", "exec", topo.router, "sysctl", "-qw", "net.ipv4.ip_forward=1"])
    cmds.append(
        [IP, "netns", "exec", topo.router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"]
    )
    for endpoint in topo.endpoints:
        cmds += _endpoint_commands(topo.router, endpoint)
    return cmds


def _endpoint_commands(router: str, e: Endpoint) -> list[list[str]]:
    cmds = [
        [IP, "link", "add", e.iface, "type", "veth", "peer", "name", e.peer],
        [IP, "link", "set", e.iface, "netns", router],
        [IP, "link", "set", e.peer, "netns", e.name],
        [IP, "-n", router, "addr", "add", e.router4, "dev", e.iface],
        [IP, "-n", e.name, "addr", "add", e.addr4, "dev", e.peer],
        [IP, "-n", router, "link", "set", e.iface, "up"],
        [IP, "-n", e.name, "link", "set", e.peer, "up"],
        [IP, "-n", e.name, "link", "set", "lo", "up"],
        [IP, "-n", e.name, "route", "add", "default", "via", e.gateway4],
    ]
    if e.router6 and e.addr6 and e.gateway6:
        cmds += [
            [IP, "-n", router, "addr", "add", e.router6, "dev", e.iface],
            [IP, "-n", e.name, "addr", "add", e.addr6, "dev", e.peer],
            [IP, "-6", "-n", e.name, "route", "add", "default", "via", e.gateway6],
        ]
    return cmds


def teardown_commands(topo: Topology) -> list[list[str]]:
    """Delete every namespace — which frees its veths — reversing :func:`setup_commands`."""
    return [[IP, "netns", "del", ns] for ns in topo.namespaces]


def load_command(router: str) -> list[str]:
    """Run ``nft`` in ``router`` reading a JSON ruleset from stdin."""
    return [IP, "netns", "exec", router, NFT, "-j", "-f", "-"]


def ping_command(src_ns: str, dst_ip: str, *, count: int = 1, family: int = 4) -> list[str]:
    """A one-second-timeout ping of ``dst_ip`` from ``src_ns`` (``family`` 4 or 6)."""
    return [
        IP, "netns", "exec", src_ns, "ping", f"-{family}", "-c", str(count), "-W", "1", dst_ip,
    ]


def render(ruleset: Ruleset) -> dict[str, Any]:
    """Render an IR ``Ruleset`` to nftables JSON — reuses the generator (task #114 seam)."""
    return generate(ruleset)


def load_payload(ruleset: Ruleset) -> dict[str, Any]:
    """The rendered ruleset prefixed with ``flush ruleset`` so a reload is deterministic."""
    rendered = render(ruleset)
    return {"nftables": [{"flush": {"ruleset": None}}, *rendered["nftables"]]}


# ---- imperative shell -------------------------------------------------------------------


class NetnsSandbox:
    """Builds a :class:`Topology` on ``__enter__`` and tears it down on ``__exit__``.

    Requires root and ``ip``/``nft`` (guard with :func:`netns_available`).
    """

    def __init__(self, topo: Topology) -> None:
        self.topo = topo

    def __enter__(self) -> NetnsSandbox:
        for cmd in setup_commands(self.topo):
            _run(cmd)
        return self

    def __exit__(self, *exc: object) -> None:
        for cmd in teardown_commands(self.topo):
            _run(cmd, check=False)

    def load(self, ruleset: Ruleset) -> None:
        """Flush and load ``ruleset`` into the router namespace."""
        _run(load_command(self.topo.router), stdin_text=json.dumps(load_payload(ruleset)))

    def ping(self, src_ns: str, dst_ip: str, *, count: int = 1, family: int = 4) -> bool:
        """True when ``src_ns`` can ping ``dst_ip`` (the packet path is open)."""
        result = _run(ping_command(src_ns, dst_ip, count=count, family=family), check=False)
        return result.returncode == 0

    def exec(
        self, ns: str, argv: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run an arbitrary command inside ``ns`` (extension point for DNAT/SNAT probes)."""
        return _run([IP, "netns", "exec", ns, *argv], check=check)


def _run(
    cmd: Sequence[str], *, check: bool = True, stdin_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd), check=check, input=stdin_text, capture_output=True, text=True
    )
