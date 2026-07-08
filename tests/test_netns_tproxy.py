"""Netns proof of the transparent-proxy mangle path: TPROXY reaches a local listener, DIVERT
keeps an established flow local, and a mangle-set mark is observable on the connection (#231).

This is the behavioral counterpart to the hermetic mangle golden test (#230): the same committed
fixture (``fixtures/mangle_tproxy_compile_dir``) is compiled end to end and loaded into a router
namespace, then real packets drive the three ADR-0042 transparent-proxy actions and assert their
packet-path effect (ARCHITECTURE.md testing pyramid #2, ``netns`` marker).

Topology: a router wired to a single ``net`` client. The client dials an *external* address
(``203.0.113.9:80``) the router has no route to — so the connection only completes if the router's
``TPROXY`` rule redirects it to the local proxy socket on :50080. Delivering a TPROXY'd packet to
the local stack is host **policy routing**, not part of the nft ruleset (Shorewall installs it
separately); the test supplies that glue — an ``iif`` rule steering the client's ingress into a
``local`` route table — exactly as :mod:`test_netns_mangle_provider` installs provider routing.

What each assertion pins (all read from a *separate* ``snf231_obs`` observation table that only
counts — it never perturbs the ruleset under test):

* **TPROXY reaches the listener** — a transparent (``IP_TRANSPARENT``) listener bound on :50080
  receives and echoes the flow, so the redirect landed on the local socket.
* **DIVERT keeps the established flow local** — established packets are matched by DIVERT's
  ``socket transparent`` rule (which precedes TPROXY) and accepted, so they are *not* re-redirected:
  the "re-steer" counter (established packets carrying TPROXY's 0x1 mark) stays 0. Its teeth are the
  sibling mutation test, where removing DIVERT lets those packets fall through to TPROXY and the
  counter rises.
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

from shorewallnf.cli import preprocess
from shorewallnf.ir import Ruleset
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
_PROXY_PORT = 50080       # the fixture's TPROXY(50080,0x1) redirect target
_TPROXY_MARK = 0x1        # TPROXY's meta mark — a re-steered established packet carries it
_CONN_MARK = 0x2          # CONNMARK(0x2/0xff) — the connection mark, observable on the flow
_ROUNDS = 4               # request/response round-trips, so established packets traverse prerouting
_RT_TABLE = 100           # the local route table the tproxy glue steers client ingress into

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

# The observation table: two count-only prerouting chains at priority -140 (just after the mangle
# chain at -150), so they read the mark the mangle chain set on the same packet without altering it.
_OBS_TABLE = (
    "table inet snf231_obs {\n"
    "  chain resteer {\n"
    "    type filter hook prerouting priority -140; policy accept\n"
    f"    ct state established meta mark {_TPROXY_MARK:#x} counter\n"
    "  }\n"
    "  chain connmark {\n"
    "    type filter hook prerouting priority -140; policy accept\n"
    f"    ct mark {_CONN_MARK:#x} counter\n"
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


def _install_proxy_glue(sb: nh.NetnsSandbox) -> None:
    """Load the observation table and the transparent-proxy policy routing into the router.

    The routing glue — a ``local`` default route in a dedicated table, selected for the client's
    ingress interface — is what delivers a TPROXY'd packet to the local stack (host config the nft
    ruleset does not carry). The observation table only counts, leaving the tested ruleset intact.
    """
    subprocess.run(
        [nh.IP, "netns", "exec", TOPO.router, nh.NFT, "-f", "-"],
        input=_OBS_TABLE, text=True, capture_output=True, check=True,
    )
    sb.exec(TOPO.router, ["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo",
                          "table", str(_RT_TABLE)])
    sb.exec(TOPO.router, ["ip", "rule", "add", "iif", CLIENT.iface, "lookup", str(_RT_TABLE)])


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


def _drive_proxy_flow(sb: nh.NetnsSandbox) -> str:
    """Dial ``_EXT_DEST:80`` from the client and run the request/response exchange; return the last
    echo the local proxy listener sent back (``E:M<n>``), or ``filtered`` if nothing arrived."""
    result = sb.exec(
        CLIENT.name,
        [nh.PY3, "-c", _PROXY_PROBE, _EXT_DEST, str(_DPORT), "3.0", str(_ROUNDS)],
        check=False,
    )
    return result.stdout.strip()


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


def _delete_divert(sb: nh.NetnsSandbox) -> None:
    """Delete the compiled DIVERT rule (``socket transparent`` + ``accept``) from the prerouting
    chain — the mutation whose effect the re-steer counter measures."""
    out = sb.exec(TOPO.router, ["nft", "-j", "list", "chain", "inet", "filter", "prerouting"])
    doc: dict[str, Any] = json.loads(out.stdout)
    for item in doc["nftables"]:
        rule = item.get("rule")
        if rule and "socket" in json.dumps(rule["expr"]) and {"accept": None} in rule["expr"]:
            sb.exec(TOPO.router, ["nft", "delete", "rule", "inet", "filter", "prerouting",
                                  "handle", str(rule["handle"])])
            return
    raise AssertionError("DIVERT rule not found in the compiled prerouting chain")


@pytest.mark.netns
@_requires_tproxy
def test_tproxy_reaches_listener_divert_keeps_flow_local_mark_observable() -> None:
    """The compiled TPROXY delivers the flow to the local proxy socket, DIVERT keeps the
    established flow local (not re-steered), and the CONNMARK mark is observable on the flow."""
    ruleset = _compile_ruleset()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        _install_proxy_glue(sb)
        with _proxy_listener(sb):
            echo = _drive_proxy_flow(sb)

        # TPROXY redirected the flow to the local :50080 listener, which echoed it back.
        assert echo == f"E:M{_ROUNDS - 1}"
        # DIVERT diverted the established packets before TPROXY, so none were re-redirected.
        assert _counter(sb, "resteer") == 0
        # CONNMARK stamped the connection; the mark is observable on the flow's packets.
        assert _counter(sb, "connmark") > 0


@pytest.mark.netns
@_requires_tproxy
def test_without_divert_established_flow_is_re_steered() -> None:
    """Teeth for the DIVERT assertion: with the DIVERT rule removed, established packets fall
    through to TPROXY and are re-redirected — the re-steer counter rises above zero."""
    ruleset = _compile_ruleset()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        _delete_divert(sb)
        _install_proxy_glue(sb)
        with _proxy_listener(sb):
            echo = _drive_proxy_flow(sb)

        assert echo == f"E:M{_ROUNDS - 1}"
        assert _counter(sb, "resteer") > 0
