"""Netns behavioral proof that a provider's fwmark steers egress (task #237, epic #204, ADR-0050).

Providers lower to a second output channel — per-provider routing tables plus ``ip rule fwmark``
selection (:func:`shorewallnf.generator.generate_routing` +
:func:`shorewallnf.applier.routing_install_argv`, task #235) — that lives in the Linux routing
subsystem, not nftables. This drives that channel on a real packet path: a router namespace with
three egress endpoints (two providers + a default uplink), the provider routing artifacts installed
in the router, and the compiled nft ruleset loaded alongside them. A probe is generated from the
firewall host (the router) with the provider's fwmark set via ``SO_MARK`` — a **minimal in-test mark
mechanism, independent of the mangle generator** (setting the mark is the mangle epic's job, #203;
composing it end to end is #204's separate criterion) — and each egress namespace runs a listener
that echoes its identity, so the identity a probe receives names the interface the packet actually
left by. A mark-1 probe must egress provider A, a mark-2 probe provider B, and an unmarked probe the
default route. Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and
runs in the privileged netns CI tier (epics #77/#78).

The firewall-host origin composes with the loaded ruleset for free: the ADR-0005 base chains accept
``output`` and fast-path established/related on ``input``, so the probe's SYN and its reply pass the
filter while ``ip rule fwmark`` alone decides the egress interface.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from shorewallnf.applier import routing_install_argv
from shorewallnf.generator import generate_routing
from shorewallnf.ir import Family, Provider, Ruleset
from tests import netns_harness as nh

# Three egress endpoints wired to the firewall host (the router namespace): two providers and a
# default uplink, each on its own subnet. Unique namespace names so the sandbox cannot collide with
# other netns tests. RFC 5737 documentation ranges only (no my_shorewall/ values). The default
# uplink's link is a /28 so the off-link probe target (below) is reachable only via a default route,
# never a connected route — the router always resolves it through a gateway that answers ARP.
PROV_A = nh.Endpoint(
    name="snf237_a", iface="v_a", peer="p_a", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
PROV_B = nh.Endpoint(
    name="snf237_b", iface="v_b", peer="p_b", addr4="198.51.100.2/24", router4="198.51.100.1/24"
)
DEFAULT = nh.Endpoint(
    name="snf237_def", iface="v_def", peer="p_def", addr4="203.0.113.2/28", router4="203.0.113.1/28"
)
TOPO = nh.Topology(router="snf237_r", endpoints=(PROV_A, PROV_B, DEFAULT))

# Two providers: A steered by fwmark 1 into table 1 out ``v_a``, B by fwmark 2 into table 2 out
# ``v_b``. The gateway is each provider endpoint's own address (it answers ARP and completes the
# handshake). The routing lowering (#234) and the ip-argv builder (#235) are exercised as written.
_PROVIDERS = Ruleset(
    providers=(
        Provider(name="wanA", number=1, mark=1, interface=PROV_A.iface,
                 gateway=PROV_A.host_ip4, family=Family.IPV4),
        Provider(name="wanB", number=2, mark=2, interface=PROV_B.iface,
                 gateway=PROV_B.host_ip4, family=Family.IPV4),
    )
)

# An off-link probe target: outside every connected subnet, so an unmarked packet takes the default
# route out ``v_def`` and a marked packet takes its provider's table. Each egress namespace holds it
# on ``lo`` so the arriving SYN is delivered locally to that namespace's listener.
_TARGET = "203.0.113.100"
_PORT = 9237

# The identity each egress namespace echoes on connect; the tag a probe receives names the interface
# the packet left by. Keyed by provider mark, with 0 for the unmarked default flow.
_TAGS = {1: "A", 2: "B", 0: "DEF"}

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)

# A one-shot TCP probe: connect to host:port, optionally stamping the socket with SO_MARK (the
# minimal, mangle-independent mark), and print the identity tag the listener echoes back. A timeout
# (the SYN was routed somewhere with no listener) reads as ``filtered``.
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

# A TCP listener bound to every interface that echoes its identity tag on each accept, so a probe
# can read which namespace answered (i.e. which interface the router egressed).
_LISTEN = (
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


def _probe(sb: nh.NetnsSandbox, mark: int, *, timeout: float = 1.0) -> str:
    """Probe ``_TARGET`` from the router with ``mark`` on the socket; return the echoed tag."""
    result = sb.exec(
        TOPO.router,
        ["python3", "-c", _MARKPROBE, _TARGET, str(_PORT), str(mark), str(timeout)],
        check=False,
    )
    return result.stdout.strip()


@contextmanager
def _egress_listeners(sb: nh.NetnsSandbox) -> Iterator[None]:
    """Run a tag-echoing listener in each egress namespace, waiting until each is accepting."""
    procs = [
        subprocess.Popen(
            ["ip", "netns", "exec", ep.name, "python3", "-c", _LISTEN, str(_PORT), _TAGS[mark]]
        )
        for mark, ep in ((1, PROV_A), (2, PROV_B), (0, DEFAULT))
    ]
    try:
        for ep, tag in ((PROV_A, "A"), (PROV_B, "B"), (DEFAULT, "DEF")):
            _await_listener(sb, ep.name, tag)
        yield
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            proc.wait()


def _await_listener(sb: nh.NetnsSandbox, ns: str, tag: str, *, attempts: int = 50) -> None:
    """Block until a loopback probe inside ``ns`` gets ``tag`` back (the listener is accepting)."""
    for _ in range(attempts):
        result = sb.exec(
            ns, ["python3", "-c", _MARKPROBE, "127.0.0.1", str(_PORT), "0", "0.2"], check=False
        )
        if result.stdout.strip() == tag:
            return
        time.sleep(0.1)
    raise RuntimeError(f"listener on {ns}:{_PORT} never came up")


def _install_routing(sb: nh.NetnsSandbox) -> None:
    """Install the provider routing artifacts and the default uplink route into the router.

    The artifacts come from the real generator/applier seam (``generate_routing`` ->
    ``routing_install_argv``), executed inside the router namespace. rp_filter is disabled so the
    reply — which arrives on the marked provider's interface but is not reachable that way in the
    main table — is not treated as a spoof.
    """
    for dev in ("all", PROV_A.iface, PROV_B.iface, DEFAULT.iface):
        sb.exec(TOPO.router, ["sysctl", "-qw", f"net.ipv4.conf.{dev}.rp_filter=0"])
    sb.exec(
        TOPO.router,
        ["ip", "route", "add", "default", "via", DEFAULT.host_ip4, "dev", DEFAULT.iface],
    )
    for argv in routing_install_argv(generate_routing(_PROVIDERS)):
        sb.exec(TOPO.router, argv)
    for ep in TOPO.endpoints:
        sb.exec(ep.name, ["ip", "addr", "add", f"{_TARGET}/32", "dev", "lo"])


@pytest.mark.netns
@_requires_netns
def test_marked_traffic_egresses_its_provider_unmarked_follows_default() -> None:
    """A mark-1 probe leaves via provider A, a mark-2 probe via provider B, unmarked via default."""
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(_PROVIDERS)  # the compiled nft ruleset loads alongside the routing artifacts
        _install_routing(sb)
        with _egress_listeners(sb):
            assert _probe(sb, mark=1) == "A"
            assert _probe(sb, mark=2) == "B"
            assert _probe(sb, mark=0) == "DEF"
