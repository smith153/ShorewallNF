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
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from shorewallnf.generator import generate
from shorewallnf.ir import Ruleset

IP = "ip"
NFT = "nft"
PY3 = "python3"  # in-namespace interpreter for the socket probes/listeners below


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


# Runs the *production* applier inside the router netns: it wraps the piped ruleset with the
# ADR-0010 scoped create-then-delete prelude and shells out to ``nft`` — never ``flush ruleset``.
_APPLY_RUNNER = (
    "import sys, json; from shorewallnf.applier import apply_ruleset; "
    "apply_ruleset(json.load(sys.stdin))"
)


def apply_command(router: str, *, python: str = sys.executable) -> list[str]:
    """Run the real applier's apply path inside ``router``, reading generated JSON from stdin.

    Unlike :func:`load_command`'s ``flush ruleset`` shortcut, this invokes
    :func:`shorewallnf.applier.apply_ruleset` — the production ADR-0010 scoped replace — so the
    load leaves co-resident (non-ShorewallNF) tables intact. ``nft`` inherits the current netns,
    hence the ``ip netns exec`` wrapper puts the apply in the router namespace.
    """
    return [IP, "netns", "exec", router, python, "-c", _APPLY_RUNNER]


def ping_command(src_ns: str, dst_ip: str, *, count: int = 1, family: int = 4) -> list[str]:
    """A one-second-timeout ping of ``dst_ip`` from ``src_ns`` (``family`` 4 or 6)."""
    return [
        IP, "netns", "exec", src_ns, "ping", f"-{family}", "-c", str(count), "-W", "1", dst_ip,
    ]


#: Render an IR ``Ruleset`` to nftables JSON. Defaults to the running generator; pass
#: ``generate_stopped`` to drive the stopped safe state (#213) through the same load seam.
Generator = Callable[[Ruleset], dict[str, Any]]


def render(ruleset: Ruleset, generator: Generator = generate) -> dict[str, Any]:
    """Render an IR ``Ruleset`` to nftables JSON — reuses ``generator`` (task #114 seam)."""
    return generator(ruleset)


def load_payload(ruleset: Ruleset, generator: Generator = generate) -> dict[str, Any]:
    """The rendered ruleset prefixed with ``flush ruleset`` so a reload is deterministic."""
    rendered = render(ruleset, generator)
    return {"nftables": [{"flush": {"ruleset": None}}, *rendered["nftables"]]}


# ---- TCP socket probes (pure planners + scripts) ----------------------------------------
#
# Two probe patterns, shared by every netns behavioral module:
#   * plain reachability — :data:`_CONNECT` prints ``open``/``refused``/``filtered`` (a RST is
#     distinguished from a silently-dropped SYN), driven by :meth:`NetnsSandbox.connect`;
#   * tag echo — :data:`_ECHO_LISTEN` sends its identity tag on accept and :data:`_MARKPROBE`
#     (optionally stamping ``SO_MARK``) prints it back, so a probe names the interface a packet
#     left by. Driven by :meth:`NetnsSandbox.probe`.
# The ``*_command`` planners return the exact ``ip netns exec … python3 -c …`` argv and are
# unit-tested without root, matching the other pure planners above.

#: One-shot TCP connect run inside a namespace: prints the reachability of ``host:port``.
#: ``ConnectionRefusedError`` (RST) is distinguished from any other ``OSError`` (a timeout means
#: the SYN was silently dropped) so a blocked port reads as ``filtered``, not ``refused``.
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

#: A trivial accept-and-close TCP listener bound to every interface (argv: ``port``).
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

#: A TCP listener that echoes its identity tag on each accept (argv: ``port tag``), so a probe
#: can read which namespace answered — i.e. which interface the router egressed by.
_ECHO_LISTEN = (
    "import socket,sys\n"
    "tag=sys.argv[2].encode()\n"
    "s=socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.bind(('0.0.0.0', int(sys.argv[1])))\n"
    "s.listen(16)\n"
    "while True:\n"
    "    try:\n"
    "        c, _ = s.accept()\n"
    "        c.sendall(tag)\n"
    "        c.close()\n"
    "    except OSError:\n"
    "        break\n"
)

#: A one-shot TCP probe (argv: ``host port mark timeout``): connect to ``host:port``, optionally
#: stamping the socket with ``SO_MARK`` (``mark`` 0 = unmarked), and print the tag the listener
#: echoes back. A timeout (routed somewhere with no listener) reads as ``filtered``.
_MARKPROBE = (
    "import socket,sys\n"
    "mark=int(sys.argv[3])\n"
    "s=socket.socket()\n"
    "s.settimeout(float(sys.argv[4]))\n"
    "if mark:\n"
    "    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)\n"
    "try:\n"
    "    s.connect((sys.argv[1], int(sys.argv[2])))\n"
    "    print(s.recv(16).decode() or 'empty')\n"
    "except OSError:\n"
    "    print('filtered')\n"
)

#: One tag-echoing listener: the namespace it runs in, the port it binds, and the tag it echoes.
ListenerSpec = tuple[str, int, str]


def connect_command(src_ns: str, host: str, port: int, *, timeout: float = 1.0) -> list[str]:
    """The argv that probes ``host:port`` from ``src_ns`` for ``open``/``refused``/``filtered``."""
    return [IP, "netns", "exec", src_ns, PY3, "-c", _CONNECT, host, str(port), str(timeout)]


def listen_command(ns: str, port: int) -> list[str]:
    """The argv that runs an accept-and-close TCP listener on ``port`` inside ``ns``."""
    return [IP, "netns", "exec", ns, PY3, "-c", _LISTEN, str(port)]


def echo_listen_command(ns: str, port: int, tag: str) -> list[str]:
    """The argv that runs a ``tag``-echoing TCP listener on ``port`` inside ``ns``."""
    return [IP, "netns", "exec", ns, PY3, "-c", _ECHO_LISTEN, str(port), tag]


def probe_command(
    src_ns: str, host: str, port: int, *, mark: int = 0, timeout: float = 1.0
) -> list[str]:
    """The argv that probes ``host:port`` from ``src_ns`` (optionally ``SO_MARK``-stamped) and
    prints the tag the listener echoes back."""
    return [
        IP, "netns", "exec", src_ns, PY3, "-c", _MARKPROBE,
        host, str(port), str(mark), str(timeout),
    ]


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

    def load(self, ruleset: Ruleset, generator: Generator = generate) -> None:
        """Flush and load ``ruleset`` into the router namespace (``generator`` selects the render
        entry point — ``generate_stopped`` for the stopped safe state, #213)."""
        _run(
            load_command(self.topo.router),
            stdin_text=json.dumps(load_payload(ruleset, generator)),
        )

    def apply(self, ruleset: Ruleset) -> None:
        """Apply ``ruleset`` into the router netns via the real applier (scoped replace, no flush).

        Exercises :func:`shorewallnf.applier.apply_ruleset` end to end — the production apply
        path the ``shorewallnf apply`` verb uses — so a re-apply replaces only ShorewallNF's own
        tables and leaves co-resident tables untouched.
        """
        _run(apply_command(self.topo.router), stdin_text=json.dumps(render(ruleset)))

    def ping(self, src_ns: str, dst_ip: str, *, count: int = 1, family: int = 4) -> bool:
        """True when ``src_ns`` can ping ``dst_ip`` (the packet path is open)."""
        result = _run(ping_command(src_ns, dst_ip, count=count, family=family), check=False)
        return result.returncode == 0

    def exec(
        self, ns: str, argv: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run an arbitrary command inside ``ns`` (extension point for DNAT/SNAT probes)."""
        return _run([IP, "netns", "exec", ns, *argv], check=check)

    def connect(
        self, src_ns: str, host: str, port: int, *, timeout: float = 1.0
    ) -> str:
        """Probe ``host:port`` from ``src_ns``: ``open``/``refused``/``filtered`` (timed out)."""
        cmd = connect_command(src_ns, host, port, timeout=timeout)
        return _run(cmd, check=False).stdout.strip()

    def probe(
        self, src_ns: str, host: str, port: int, *, mark: int = 0, timeout: float = 1.0
    ) -> str:
        """Probe ``host:port`` from ``src_ns`` (optionally ``SO_MARK`` ``mark``) and return the tag
        the listener echoes back (``filtered`` on timeout)."""
        return _run(
            probe_command(src_ns, host, port, mark=mark, timeout=timeout), check=False
        ).stdout.strip()


def _run(
    cmd: Sequence[str], *, check: bool = True, stdin_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd), check=check, input=stdin_text, capture_output=True, text=True
    )


# ---- listener lifecycles (imperative) ---------------------------------------------------


@contextmanager
def listeners(sb: NetnsSandbox, ns: str, ports: Sequence[int]) -> Iterator[None]:
    """Run one accept-and-close TCP listener per port in ``ns`` for the duration of the block,
    waiting until each is accepting before yielding so a probe can never race the bind."""
    procs = [subprocess.Popen(listen_command(ns, port)) for port in ports]
    try:
        for port in ports:
            _await(sb, ns, port, "open")
        yield
    finally:
        _reap(procs)


@contextmanager
def echo_listeners(sb: NetnsSandbox, specs: Sequence[ListenerSpec]) -> Iterator[None]:
    """Run each ``(ns, port, tag)`` tag-echoing listener for the duration of the block, waiting
    until each is accepting (its tag comes back on a loopback probe) before yielding."""
    procs = [subprocess.Popen(echo_listen_command(ns, port, tag)) for ns, port, tag in specs]
    try:
        for ns, port, tag in specs:
            _await(sb, ns, port, tag)
        yield
    finally:
        _reap(procs)


def _await(sb: NetnsSandbox, ns: str, port: int, expect: str, *, attempts: int = 50) -> None:
    """Block until a loopback probe inside ``ns`` sees its listener accept. ``expect`` is ``open``
    for a plain :func:`listeners` port (polled via :meth:`NetnsSandbox.connect`) or the echoed tag
    for an :func:`echo_listeners` port (polled via :meth:`NetnsSandbox.probe`); the loopback hop is
    admitted by the no-lockout baseline, so this confirms the bind, not the firewall."""
    for _ in range(attempts):
        got = (
            sb.connect(ns, "127.0.0.1", port, timeout=0.2)
            if expect == "open"
            else sb.probe(ns, "127.0.0.1", port, timeout=0.2)
        )
        if got == expect:
            return
        time.sleep(0.1)
    raise RuntimeError(f"listener on {ns}:{port} never came up")


def _reap(procs: Sequence[subprocess.Popen[bytes]]) -> None:
    for proc in procs:
        proc.terminate()
    for proc in procs:
        proc.wait()
