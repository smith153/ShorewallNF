"""Netns proof that ShorewallNF's ``CLAMPMSS`` rewrites the TCP MSS option in **both** handshake
directions of a forwarded connection (#368, #375).

The forward-path MSS clamp (:func:`shorewallnf.generator._clampmss`, ADR-0061) mangles the MSS
option of forwarded SYNs. The hermetic golden tier pins the emitted JSON and ``nft --check``; this
behavioral tier proves the compiled rule actually clamps real packets: a client namespace opens a
TCP connection to a listener in a server namespace **through** the router (so the handshake
traverses the forward chain), while raw-socket capturers read the MSS option off both handshake
packets — the forward SYN (arriving at the server) and the return SYN-ACK (arriving at the client)
— and assert each equals the configured size.

The return SYN-ACK is the #375 regression guard: conntrack classifies it as ct-state
``established`` (the reply to a NEW connection), so a clamp placed *behind* the forward
established/related accept never sees it and the client would read the server's un-clamped MSS.
Capturing it here fails the test if the clamp ever regresses to that placement.

The fixed-int variant is the behavioral bar (issue #368); the ``Yes``/path-MTU form is covered by
the golden + ``nft --check`` tier, since a faithful path-MTU setup is disproportionately heavy.

Topology: ``client`` -- ``router`` -- ``server``, RFC 5737 ranges only. Gated on the ``netns``
marker + root, so it skips cleanly in the hermetic tier and runs in the privileged netns CI tier.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from shorewallnf.ir import Family, Policy, Ruleset, Settings, Zone, ZoneMember
from tests import netns_harness as nh

# Router wired to a traffic-originating client and a server, each ``iface`` naming the zone's
# router-side veth. Unique namespace names so the sandbox never collides with other netns tests.
CLIENT = nh.Endpoint(
    name="snf368_cli", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
SERVER = nh.Endpoint(
    name="snf368_srv", iface="v_srv", peer="p_srv",
    addr4="198.51.100.2/24", router4="198.51.100.1/24",
)
TOPO = nh.Topology(router="snf368_r", endpoints=(CLIENT, SERVER))

ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="client", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
    Zone(name="server", members=(ZoneMember(interface="v_srv", family=Family.BOTH),)),
)
# The forward chain default-drops, and the clamp is non-terminating — so the clamped SYN needs an
# explicit forward ACCEPT to reach the server (and be captured).
POLICIES = (Policy(source="client", dest="server", action="ACCEPT"),)

_PORT = 9368
_CLAMP = 500  # < a 1500-MTU link's 1460 default MSS, so the clamp visibly lowers the option

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)

# Raw-socket capturer (argv: ``timeout port want_ack``): reads incoming TCP and finds the first
# handshake packet for the connection to server ``port`` — the forward SYN (``want_ack=0``: SYN set,
# ACK clear, matched on dport) or the return SYN-ACK (``want_ack=1``: SYN+ACK set, matched on the
# server's sport). Prints its MSS option value (nft ``maxseg``/kind 2), ``nomss`` if it carries
# none, ``timeout`` if none arrives.
_CAPTURE = (
    "import socket,struct,sys\n"
    "s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\n"
    "s.settimeout(float(sys.argv[1]))\n"
    "port=int(sys.argv[2])\n"
    "want_ack=int(sys.argv[3])\n"
    "try:\n"
    "    while True:\n"
    "        pkt=s.recv(65535)\n"
    "        ihl=(pkt[0]&0x0F)*4\n"
    "        tcp=pkt[ihl:]\n"
    "        if len(tcp)<20:\n"
    "            continue\n"
    "        sport,dport=struct.unpack('!HH', tcp[0:4])\n"
    "        flags=tcp[13]\n"
    "        if not (flags&0x02) or bool(flags&0x10)!=bool(want_ack):\n"
    "            continue\n"
    "        if (sport if want_ack else dport)!=port:\n"
    "            continue\n"
    "        doff=(tcp[12]>>4)*4\n"
    "        opts=tcp[20:doff]\n"
    "        i=0\n"
    "        while i<len(opts):\n"
    "            kind=opts[i]\n"
    "            if kind==0:\n"
    "                break\n"
    "            if kind==1:\n"
    "                i+=1; continue\n"
    "            olen=opts[i+1]\n"
    "            if kind==2 and olen==4:\n"
    "                print(struct.unpack('!H', opts[i+2:i+4])[0]); sys.exit(0)\n"
    "            i+=olen\n"
    "        print('nomss'); sys.exit(0)\n"
    "except socket.timeout:\n"
    "    print('timeout'); sys.exit(0)\n"
)


def _capture_command(ns: str, port: int, *, want_ack: bool, timeout: float) -> list[str]:
    argv = [str(timeout), str(port), str(int(want_ack))]
    return [nh.IP, "netns", "exec", ns, nh.PY3, "-c", _CAPTURE, *argv]


@pytest.mark.netns
@_requires_netns
def test_forwarded_handshake_mss_is_clamped_both_directions() -> None:
    """Both handshake directions are clamped: the forwarded SYN (client->server) and the return
    SYN-ACK (server->client). The SYN-ACK arm is the #375 regression guard — it is ct-state
    established, so a clamp placed behind the forward established/related accept would leave the
    client reading the server's un-clamped MSS, failing this assertion."""
    ruleset = Ruleset(zones=ZONES, policies=POLICIES, settings=Settings(clampmss=_CLAMP))
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(ruleset)
        # A real listener so the server answers with a SYN-ACK to capture (not a bare RST).
        with nh.listeners(sb, SERVER.name, [_PORT]):
            syn = subprocess.Popen(
                _capture_command(SERVER.name, _PORT, want_ack=False, timeout=5.0),
                stdout=subprocess.PIPE,
                text=True,
            )
            synack = subprocess.Popen(
                _capture_command(CLIENT.name, _PORT, want_ack=True, timeout=5.0),
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                time.sleep(0.5)  # let both raw sockets open before the handshake
                sb.connect(CLIENT.name, SERVER.host_ip4, _PORT, timeout=2.0)
                syn_out, _ = syn.communicate(timeout=8)
                synack_out, _ = synack.communicate(timeout=8)
            finally:
                for cap in (syn, synack):
                    if cap.poll() is None:
                        cap.terminate()
                        cap.wait()
        assert syn_out.strip() == str(_CLAMP)  # forward SYN (clamped in either placement)
        # return SYN-ACK (clamped only when the rule sits ahead of the established accept)
        assert synack_out.strip() == str(_CLAMP)
