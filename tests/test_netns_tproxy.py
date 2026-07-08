"""Netns proof of the transparent-proxy mangle path: TPROXY reaches a local listener via the
*compiled* fwmark local-delivery routing, DIVERT keeps an established flow local, and a mangle-set
mark is observable on the connection (#231, ADR-0051 #295).

This is the behavioral counterpart to the hermetic mangle golden test (#230): the same committed
fixture (``fixtures/mangle_tproxy_compile_dir``) is compiled end to end and loaded into a router
namespace, then real packets drive the ADR-0042 transparent-proxy actions and assert their
packet-path effect (ARCHITECTURE.md testing pyramid #2, ``netns`` marker).

Topology: a router wired to a single ``net`` client. The client dials an *external* address
(``203.0.113.9:80``) the router has no route to — so the connection only completes if the router's
``TPROXY`` rule redirects it to the local proxy socket on :50080 **and** the packet is delivered to
the local stack. That local delivery is host **policy routing** (Shorewall installs it separately),
and ADR-0051 makes the compiler emit it: the generator injects the reserved ``TPROXY_MARK``
(``0xffffffff``) on both DIVERT and TPROXY (#292) and emits a :class:`TproxyRoutingArtifact` (#293)
that the applier lowers to ``ip rule fwmark 0xffffffff`` + a ``local`` route (#294). This test
installs that *compiler-emitted* glue via the real ``generate_tproxy_routing`` /
``tproxy_routing_install_argv`` seam — the idiomatic fwmark path — dropping the earlier
``ip rule iif <iface>`` workaround #231 needed before the mark existed (#272).

What each assertion pins (the mark counters are read from a *separate* ``snf231_obs`` observation
table that only counts — it never perturbs the ruleset under test):

* **TPROXY reaches the listener via fwmark** — a transparent (``IP_TRANSPARENT``) listener bound on
  :50080 receives and echoes the whole flow, so the ``fwmark 0xffffffff`` route delivered both the
  new connection (TPROXY) and the established/half-open packets (DIVERT) to the local socket. The
  #272 misdelivery — a half-open retransmit SYN matching the markless ``socket transparent`` rule
  being forwarded (ICMP net-unreachable) instead of delivered locally — no longer occurs.
* **DIVERT keeps the established flow local** — established packets match DIVERT's
  ``socket transparent`` rule (which precedes TPROXY) and carry the reserved fwmark it stamps, so
  the ``ip rule fwmark`` route keeps them local. Its teeth are the sibling test: with the compiled
  fwmark glue absent, nothing routes the TPROXY'd packet to the local stack and the flow is never
  delivered (the echo never comes back).
* **The mark is observable** — CONNMARK stamps the connection ``ct mark 0x2``, counted per packet.

Needs root + ``ip``/``nft`` and the ``nft_tproxy``/``nft_socket`` kernel modules; skips cleanly
where absent (hermetic tier stays green), runs in the privileged netns CI tier.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from shorewallnf.applier import tproxy_routing_install_argv
from shorewallnf.cli import preprocess
from shorewallnf.generator import generate_tproxy_routing
from shorewallnf.ir import TPROXY_MARK, Ruleset
from shorewallnf.parser import parse_config
from shorewallnf.resolver import resolve
from shorewallnf.validator import validate
from tests import netns_harness as nh

# The committed config dir compiled end to end. Its ``interfaces`` file names the router-side veth
# below (``v_net``) verbatim, and its ``mangle`` rules CONNMARK/DIVERT/TPROXY the tcp/80 flow.
_FIXTURE = Path(__file__).parent / "fixtures" / "mangle_tproxy_compile_dir"

# A router wired to one ``net`` client. Unique namespace names so the sandbox can't collide with
# other netns modules; the veth name matches the fixture's ``interfaces`` entry. RFC 5737 ranges.
CLIENT = nh.Endpoint(
    name="snf231_net", iface="v_net", peer="p_net",
    addr4="198.51.100.2/24", router4="198.51.100.1/24",
)
TOPO = nh.Topology(router="snf231_r", endpoints=(CLIENT,))

_EXT_DEST = "203.0.113.9"  # external addr the client dials; the router has no route there
_DPORT = 80               # the fixture's CONNMARK/TPROXY match tcp dport 80
_PROXY_PORT = 50080       # the fixture's TPROXY(50080) redirect target
_TPROXY_MARK = TPROXY_MARK  # the reserved fwmark (0xffffffff) the generator injects on DIVERT and
#                             TPROXY (ADR-0051 Part A); the compiled `ip rule fwmark` consumes it
_CONN_MARK = 0x2          # CONNMARK(0x2/0xff) — the connection mark, observable on the flow
_ROUNDS = 4               # request/response round-trips, so established packets hit prerouting

# A transparent (IP_TRANSPARENT) listener that echoes each request ``<rounds>`` times, so the
# redirected connection produces a multi-packet established exchange. argv: ``port rounds``.
_PROXY_LISTEN = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.setsockopt(socket.SOL_IP, getattr(socket, 'IP_TRANSPARENT', 19), 1)\n"
    "s.bind(('0.0.0.0', int(sys.argv[1])))\n"
    "s.listen(16)\n"
    "while True:\n"
    "    try:\n"
    "        c, _ = s.accept()\n"
    "        for _ in range(int(sys.argv[2])):\n"
    "            data = c.recv(64)\n"
    "            if not data:\n"
    "                break\n"
    "            c.sendall(b'E:' + data)\n"
    "        c.close()\n"
    "    except OSError:\n"
    "        break\n"
)

# The client: connect to ``host:port`` and run ``rounds`` request/response exchanges, printing the
# last echo (``E:M<n>``), or ``filtered`` if nothing arrived. argv: ``host port timeout rounds``.
_PROXY_PROBE = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.settimeout(float(sys.argv[3]))\n"
    "try:\n"
    "    s.connect((sys.argv[1], int(sys.argv[2])))\n"
    "    last=''\n"
    "    for i in range(int(sys.argv[4])):\n"
    "        s.sendall(b'M%d' % i)\n"
    "        last = s.recv(64).decode()\n"
    "    print(last or 'empty')\n"
    "except OSError:\n"
    "    print('filtered')\n"
)

# The observation table: count-only prerouting chains at priority -140 (just after the mangle chain
# at -150), so they read what the mangle chain set on the same packet without altering it.
#   * `divert` counts established packets that match DIVERT's own criteria — a local transparent
#     socket exists (`socket transparent`) — *and* carry the reserved fwmark DIVERT stamps, i.e. the
#     packets DIVERT keeps local and routes to the local stack via `ip rule fwmark`.
#   * `resyn` narrows that to a *pure SYN* on an already-replied (established) connection: a
#     half-open retransmit SYN — the exact packet #272 documented being misdelivered — matching
#     DIVERT and carrying the reserved fwmark.
#   * `connmark` counts packets carrying the CONNMARK-stamped connection mark.
_OBS_TABLE = (
    "table inet snf231_obs {\n"
    "  chain divert {\n"
    "    type filter hook prerouting priority -140; policy accept\n"
    f"    ct state established socket transparent 1 meta mark {_TPROXY_MARK:#x} counter\n"
    "  }\n"
    "  chain resyn {\n"
    "    type filter hook prerouting priority -140; policy accept\n"
    "    tcp flags & (fin|syn|rst|ack) == syn ct state established "
    f"meta mark {_TPROXY_MARK:#x} counter\n"
    "  }\n"
    "  chain connmark {\n"
    "    type filter hook prerouting priority -140; policy accept\n"
    f"    ct mark {_CONN_MARK:#x} counter\n"
    "  }\n"
    "}\n"
)

# A throwaway table that drops the router's outgoing SYN-ACK to the client, so the client is forced
# to retransmit its SYN while the router already holds a half-open (SYN_RECV) transparent socket —
# the #272 case. Separate from the tested ruleset; deleted to let the handshake finally complete.
_DROP_SYNACK = (
    "table inet snf231_drop {\n"
    "  chain out {\n"
    "    type filter hook postrouting priority 0; policy accept\n"
    f'    oifname "{CLIENT.iface}" tcp flags & (syn|ack) == (syn|ack) counter drop\n'
    "  }\n"
    "}\n"
)

_MODULES = ("nft_tproxy", "nf_tproxy_ipv4", "nf_tproxy_ipv6", "nft_socket")


def _tproxy_available() -> bool:
    """True when the behavioral tproxy path can run: a netns sandbox plus the tproxy/socket
    modules (best-effort ``modprobe``, so a stock kernel that ships them loads them on demand)."""
    if not nh.netns_available():
        return False
    return all(
        subprocess.run(["modprobe", m], capture_output=True).returncode == 0 for m in _MODULES
    )


_requires_tproxy = pytest.mark.skipif(
    not _tproxy_available(),
    reason="netns transparent-proxy tier needs root + ip/nft + nft_tproxy/nft_socket modules",
)


def _compile_ruleset() -> Ruleset:
    """Compile the committed fixture through the real pipeline (preprocess -> validate)."""
    return validate(resolve(parse_config(preprocess(_FIXTURE))))


def _load_obs_table(sb: nh.NetnsSandbox) -> None:
    """Load the count-only observation table into the router (leaves the tested ruleset intact)."""
    subprocess.run(
        [nh.IP, "netns", "exec", TOPO.router, nh.NFT, "-f", "-"],
        input=_OBS_TABLE, text=True, capture_output=True, check=True,
    )


def _install_tproxy_routing(sb: nh.NetnsSandbox, ruleset: Ruleset) -> None:
    """Install the *compiler-emitted* transparent-proxy local-delivery routing into the router.

    Straight off the real generator/applier seam (``generate_tproxy_routing`` ->
    ``tproxy_routing_install_argv``, ADR-0051 #293/#294): the ``ip rule fwmark 0xffffffff`` + the
    ``local`` route out ``lo`` in the reserved table. This is the idiomatic fwmark glue the compiler
    now produces — it replaces the ``ip rule iif <iface> lookup T`` workaround #231 needed before
    the generator injected the shared TPROXY_MARK (#272). A TPROXY'd or DIVERTed packet carries the
    reserved fwmark, so this one rule delivers new *and* established/half-open packets locally.
    """
    for argv in tproxy_routing_install_argv(generate_tproxy_routing(ruleset)):
        sb.exec(TOPO.router, argv)


@contextmanager
def _proxy_listener(sb: nh.NetnsSandbox) -> Iterator[None]:
    """Run the transparent proxy listener on :50080 in the router for the block, waiting until it
    accepts (a loopback connect returns ``open``) so a probe can never race the bind."""
    proc = subprocess.Popen(
        [nh.IP, "netns", "exec", TOPO.router, nh.PY3, "-c", _PROXY_LISTEN,
         str(_PROXY_PORT), str(_ROUNDS)]
    )
    try:
        for _ in range(50):
            if sb.connect(TOPO.router, "127.0.0.1", _PROXY_PORT, timeout=0.2) == "open":
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("transparent proxy listener never came up")
        yield
    finally:
        proc.terminate()
        proc.wait()


def _drive_proxy_flow(sb: nh.NetnsSandbox, *, timeout: float = 3.0) -> str:
    """Dial ``_EXT_DEST:80`` from the client and run the request/response exchange; return the last
    echo the local proxy listener sent back (``E:M<n>``), or ``filtered`` if nothing arrived."""
    result = sb.exec(
        CLIENT.name,
        [nh.PY3, "-c", _PROXY_PROBE, _EXT_DEST, str(_DPORT), str(timeout), str(_ROUNDS)],
        check=False,
    )
    return result.stdout.strip()


def _start_proxy_flow(sb: nh.NetnsSandbox, *, timeout: float) -> subprocess.Popen[str]:
    """Start the client request/response exchange in the background (so the caller can act while the
    connection is mid-handshake). ``timeout`` must outlast the forced SYN retransmissions."""
    return subprocess.Popen(
        [nh.IP, "netns", "exec", CLIENT.name, nh.PY3, "-c", _PROXY_PROBE,
         _EXT_DEST, str(_DPORT), str(timeout), str(_ROUNDS)],
        stdout=subprocess.PIPE, text=True,
    )


def _install_synack_drop(sb: nh.NetnsSandbox) -> None:
    """Drop the router's outgoing SYN-ACK to the client, forcing a half-open retransmit SYN."""
    subprocess.run(
        [nh.IP, "netns", "exec", TOPO.router, nh.NFT, "-f", "-"],
        input=_DROP_SYNACK, text=True, capture_output=True, check=True,
    )


def _remove_synack_drop(sb: nh.NetnsSandbox) -> None:
    """Remove the SYN-ACK drop so the handshake can complete."""
    sb.exec(TOPO.router, ["nft", "delete", "table", "inet", "snf231_drop"])


def _await_counter(sb: nh.NetnsSandbox, chain: str, *, attempts: int = 50) -> int:
    """Poll observation ``chain`` until its counter is non-zero (the awaited packet arrived),
    returning the count; raise if it never does. Robust to RTO jitter — no fixed sleep."""
    for _ in range(attempts):
        count = _counter(sb, chain)
        if count > 0:
            return count
        time.sleep(0.1)
    raise AssertionError(f"observation chain {chain} never counted a packet")


def _counter(sb: nh.NetnsSandbox, chain: str) -> int:
    """The packet count of the single ``counter`` in observation chain ``chain``."""
    out = sb.exec(TOPO.router, ["nft", "-j", "list", "chain", "inet", "snf231_obs", chain])
    doc: dict[str, Any] = json.loads(out.stdout)
    for item in doc["nftables"]:
        rule = item.get("rule")
        if not rule:
            continue
        for expr in rule["expr"]:
            if isinstance(expr, dict) and "counter" in expr:
                packets: int = expr["counter"]["packets"]
                return packets
    raise AssertionError(f"no counter found in chain {chain}")


@pytest.mark.netns
@_requires_tproxy
def test_tproxy_reaches_listener_divert_keeps_flow_local_mark_observable() -> None:
    """The compiled TPROXY + fwmark routing delivers the whole flow to the local proxy socket,
    DIVERT keeps the established/half-open packets local via the shared reserved fwmark, and the
    CONNMARK mark is observable on the flow — all through the compiler-emitted glue, no iif hack."""
    ruleset = _compile_ruleset()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        _load_obs_table(sb)
        _install_tproxy_routing(sb, ruleset)
        with _proxy_listener(sb):
            echo = _drive_proxy_flow(sb)

        # TPROXY delivered the new connection and DIVERT kept the established/half-open packets
        # local — every packet routed to the :50080 listener via the compiled `fwmark 0xffffffff`
        # route, so the multi-round exchange echoes back (the #272 misdelivery no longer occurs).
        assert echo == f"E:M{_ROUNDS - 1}"
        # CONNMARK stamped the connection; the mark is observable on the flow's packets. Asserted
        # ahead of the DIVERT counter so a mark-visibility regression reports directly (#292 note).
        assert _counter(sb, "connmark") > 0
        # DIVERT kept the established flow local: established packets matched `socket transparent`
        # and carry the reserved fwmark that the `ip rule fwmark` route delivers to the local stack.
        assert _counter(sb, "divert") > 0


@pytest.mark.netns
@_requires_tproxy
def test_half_open_retransmit_syn_matches_divert_and_is_delivered_locally() -> None:
    """The #272 case, now fixed by the compiled fwmark path: a half-open retransmit SYN matches the
    DIVERT ``socket transparent`` rule and is delivered locally, not forwarded/net-unreachable.

    The router's outgoing SYN-ACK is dropped, so the client retransmits its SYN while the router
    holds a half-open transparent socket. That retransmit SYN — a *pure SYN* on an already-replied
    connection — must match DIVERT (``resyn`` counts it: reserved fwmark + established) *before* the
    handshake can complete; then, with the drop lifted, the whole flow lands on the local listener.
    """
    ruleset = _compile_ruleset()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        _load_obs_table(sb)
        _install_tproxy_routing(sb, ruleset)
        _install_synack_drop(sb)  # force the client to retransmit its SYN
        with _proxy_listener(sb):
            proc = _start_proxy_flow(sb, timeout=15.0)  # outlasts the dropped-SYN-ACK retransmits
            try:
                # The half-open retransmit SYN reaches the router and matches DIVERT — counted while
                # the SYN-ACK is still dropped, so the handshake cannot yet have completed.
                retransmit_hits = _await_counter(sb, "resyn")
                _remove_synack_drop(sb)  # let the next SYN-ACK through so the handshake finishes
                echo = (proc.communicate(timeout=20)[0] or "").strip()
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait()

        # A half-open retransmit SYN matched DIVERT's `socket transparent` rule and carried the
        # reserved fwmark (delivered locally, not the #272 net-unreachable misdelivery)...
        assert retransmit_hits >= 1
        # ...and the whole flow reached the local listener via the compiled fwmark path.
        assert echo == f"E:M{_ROUNDS - 1}"


@pytest.mark.netns
@_requires_tproxy
def test_without_fwmark_glue_tproxy_flow_is_not_delivered_locally() -> None:
    """Teeth for the compiled fwmark path: with the local-delivery routing absent, the TPROXY'd
    packet is marked but nothing routes it to the local stack, so it is never delivered — the
    listener never sees the flow and the echo never comes back."""
    ruleset = _compile_ruleset()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)  # the compiled nft ruleset, but *without* `_install_tproxy_routing`
        with _proxy_listener(sb):
            echo = _drive_proxy_flow(sb)

        assert echo != f"E:M{_ROUNDS - 1}"
