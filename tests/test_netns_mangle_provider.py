"""Netns proof that a ShorewallNF mangle-set mark steers a forwarded flow out its provider (#238).

The mangle → provider composition is the cross-epic integration point of the providers epic
(#204) with mangle (#203): a ``mangle`` rule stamps a provider's fwmark on a matched flow in
prerouting (:func:`shorewallnf.generator._mangle_rules`, task #229), and the provider's
``ip rule fwmark`` selection (:func:`shorewallnf.generator.generate_routing` +
:func:`shorewallnf.applier.routing_install_argv`, tasks #234/#235) routes that mark out the
provider's interface. Unlike the sibling test (#237, ``test_netns_providers``) which stamps the
mark with an in-test ``SO_MARK`` shim, here the mark comes **only** from ShorewallNF's own
compiled ruleset — nothing in the test sets it.

Both channels are driven from a single committed fixture (``fixtures/mangle_provider_compile_dir``)
compiled end to end: the nft ruleset (with the mangle mark rule) is loaded into the router, and the
provider routing artifacts are installed alongside it. The flow is **forwarded** — originated in a
client namespace, not the router — because the mangle chain hooks prerouting and only sees
forwarded/ingress traffic, never the router's own locally-generated packets.

Topology: a router wired to a client and two egress namespaces (provider ``wanA`` + a default
uplink), each egress holding an off-link target on ``lo`` and echoing its identity on connect, so
the tag a probe receives names the interface the packet actually left by. A probe to the
mangle-matched port must egress ``wanA`` (tag ``A``); a probe to an unmatched control port must
follow the default route (tag ``DEF``). The default uplink also answers the matched port, so a mark
that fails to fire is caught as ``DEF`` rather than passing silently. Gated on the ``netns`` marker
+ root, so it skips cleanly in the hermetic tier and runs in the privileged netns CI tier.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewallnf.applier import routing_install_argv
from shorewallnf.cli import preprocess
from shorewallnf.generator import generate_routing
from shorewallnf.ir import Ruleset
from shorewallnf.parser import parse_config
from shorewallnf.resolver import resolve
from shorewallnf.validator import validate
from tests import netns_harness as nh

# The committed config dir compiled end to end (nft ruleset + provider routing). Its ``interfaces``
# file names the router-side veths below verbatim, and its ``mangle`` rule marks tcp dport 9238.
_FIXTURE = Path(__file__).parent / "fixtures" / "mangle_provider_compile_dir"

# Router wired to a traffic-originating client and two egress endpoints. Each ``iface`` matches the
# fixture's ``interfaces`` entry exactly (the zone's router-side veth). Unique namespace names so
# the sandbox cannot collide with other netns tests. RFC 5737 documentation ranges only. The
# default uplink's link is a /28 so the off-link target is reachable only via a route, never a
# connected one.
CLIENT = nh.Endpoint(
    name="snf238_cli", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
WAN = nh.Endpoint(
    name="snf238_wan", iface="v_wan", peer="p_wan",
    addr4="198.51.100.2/24", router4="198.51.100.1/24",
)
DEFAULT = nh.Endpoint(
    name="snf238_dfl", iface="v_dfl", peer="p_dfl", addr4="203.0.113.2/28", router4="203.0.113.1/28"
)
TOPO = nh.Topology(router="snf238_r", endpoints=(CLIENT, WAN, DEFAULT))

# An off-link target held on ``lo`` in each egress namespace: outside every connected subnet, so an
# unmarked packet takes the default route out ``v_dfl`` and a marked packet takes provider wanA's
# table out ``v_wan``. Both flows share this destination — only the fwmark differs their egress.
_TARGET = "203.0.113.100"
_MARK_PORT = 9238  # the fixture's mangle rule marks tcp dport 9238 -> provider wanA (fwmark 1)
_CTRL_PORT = 9239  # a control port the mangle rule does not match -> default route

# Egress listeners as ``(namespace, port, tag)``. wanA answers the marked port; the default uplink
# answers both ports, so a probe that fails to get marked is caught as ``DEF`` on the marked port
# (not silently dropped) — the assertions' teeth.
_LISTENERS = (
    (WAN.name, _MARK_PORT, "A"),
    (DEFAULT.name, _MARK_PORT, "DEF"),
    (DEFAULT.name, _CTRL_PORT, "DEF"),
)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _compile_ruleset() -> Ruleset:
    """Compile the committed fixture through the real pipeline (preprocess -> validate)."""
    return validate(resolve(parse_config(preprocess(_FIXTURE))))


def _probe(sb: nh.NetnsSandbox, port: int, *, timeout: float = 2.0) -> str:
    """Probe ``_TARGET:port`` from the client namespace (no SO_MARK — any mark on the flow can only
    come from ShorewallNF's compiled mangle rule); return the echoed tag."""
    return sb.probe(CLIENT.name, _TARGET, port, timeout=timeout)


def _install_routing(sb: nh.NetnsSandbox, ruleset: Ruleset) -> None:
    """Install the default uplink route + the compiled provider routing artifacts into the router.

    The provider artifacts come from the real generator/applier seam
    (``generate_routing`` -> ``routing_install_argv``). rp_filter is disabled so the reply — which
    arrives on the marked provider's interface but is not reachable that way in the main table — is
    not treated as a spoof. Each egress namespace holds the off-link target on ``lo``.
    """
    for dev in ("all", CLIENT.iface, WAN.iface, DEFAULT.iface):
        sb.exec(TOPO.router, ["sysctl", "-qw", f"net.ipv4.conf.{dev}.rp_filter=0"])
    sb.exec(
        TOPO.router,
        ["ip", "route", "add", "default", "via", DEFAULT.host_ip4, "dev", DEFAULT.iface],
    )
    for argv in routing_install_argv(generate_routing(ruleset)):
        sb.exec(TOPO.router, argv)
    for ep in (WAN, DEFAULT):
        sb.exec(ep.name, ["ip", "addr", "add", f"{_TARGET}/32", "dev", "lo"])


@pytest.mark.netns
@_requires_netns
def test_mangle_mark_steers_matched_flow_out_provider_unmatched_takes_default() -> None:
    """The mangle-matched flow egresses provider wanA; an unmatched control flow takes default."""
    ruleset = _compile_ruleset()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)  # the compiled nft ruleset (with the mangle mark rule) loads here
        _install_routing(sb, ruleset)
        with nh.echo_listeners(sb, _LISTENERS):
            assert _probe(sb, _MARK_PORT) == "A"
            assert _probe(sb, _CTRL_PORT) == "DEF"
