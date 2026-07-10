"""Netns behavioral proof of the tcpflags illegal-flag check (#381, epic #310, ADR-0063 §2).

An interface carrying ``tcpflags`` gets, at the head of both the ``input`` and ``forward`` base
chains (ahead of the ADR-0005 established/related accept), one gated rule per nonsensical TCP-flag
combination → disposition (default DROP). This drives that on a real forwarded packet.

Topology: a firewall host (the router namespace) between a client and a server, each on its own
RFC 5737 subnet. The client crafts a raw TCP segment with an invalid flag combination (SYN+FIN)
addressed to the server and the router forwards it; a passive ``AF_PACKET`` sniffer on the
server-side veth reports whether the packet made it across. Because the drop happens in the
router's ``forward`` chain, the sniffer is the clean observable: it sees the segment only when the
router forwarded it.

Signals:
  * with ``tcpflags`` on ``v_cli``, the SYN+FIN segment is dropped in ``forward`` → never arrives;
  * without the option the identical segment is forwarded → arrives — proving the rule, not the
    topology, blocks it;
  * a non-default REJECT disposition still blocks it (the emitted verdict identity is pinned by the
    golden tests).

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 documentation ranges only; pure-stdlib packet
crafting (no scapy / extra runtime deps).
"""

from __future__ import annotations

import subprocess
import time

import pytest

from shorewallnf.ir import (
    Disposition,
    Family,
    Interface,
    Policy,
    Ruleset,
    Settings,
    Zone,
    ZoneMember,
)
from tests import netns_harness as nh

_CLIENT = nh.Endpoint(
    name="snf381_c", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_SERVER = nh.Endpoint(
    name="snf381_s", iface="v_srv", peer="p_srv", addr4="198.51.100.2/24", router4="198.51.100.1/24"
)
_TOPO = nh.Topology(router="snf381_r", endpoints=(_CLIENT, _SERVER))

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="cli", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
    Zone(name="srv", members=(ZoneMember(interface="v_srv", family=Family.BOTH),)),
)
# Allow client→server forwarding, so with tcpflags OFF the crafted segment reaches the server; the
# tcpflags check (ahead of this policy) is the only thing that drops it when the option is on.
_POLICIES = (Policy(source="cli", dest="srv", action="ACCEPT"),)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)

# A raw-socket sender: build an IPv4 + TCP segment with a chosen flag byte (argv: src dst flags)
# and transmit it toward dst repeatedly. IP_HDRINCL with a zero IP checksum lets the kernel fill
# the IP checksum in; the TCP checksum is computed over the standard pseudo-header. SYN+FIN (0x03)
# is one of the illegal combinations Shorewall's setup_tcp_flags rejects.
_SEND = r"""
import socket, struct, sys, time

def _csum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff

src, dst, flags = sys.argv[1], sys.argv[2], int(sys.argv[3])
sport, dport, seq, off, win = 40000, 80, 0, (5 << 4), 1024
src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, off, flags, win, 0, 0)
pseudo = src_b + dst_b + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp)) + tcp[18:]
ip = struct.pack(
    "!BBHHHBBH4s4s", (4 << 4) + 5, 0, 20 + len(tcp), 0, 0, 64, socket.IPPROTO_TCP, 0, src_b, dst_b
)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(30):
    s.sendto(ip + tcp, (dst, 0))
    time.sleep(0.03)
"""

# A passive sniffer on the server-side veth (argv: iface want_src timeout): print `got` on the
# first TCP frame from want_src, else `none` after the timeout. AF_PACKET sees the frame at the
# device, i.e. only if the router forwarded it.
_SNIFF = r"""
import socket, sys, time

iface, want_src, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  # ETH_P_IP
s.bind((iface, 0))
s.settimeout(0.3)
deadline = time.time() + timeout
while time.time() < deadline:
    try:
        frame = s.recv(65535)
    except socket.timeout:
        continue
    ip = frame[14:]  # strip the Ethernet header
    if len(ip) >= 20 and ip[9] == 6 and socket.inet_ntoa(ip[12:16]) == want_src:
        print("got")
        sys.exit(0)
print("none")
"""

_SYN_FIN = 0x03  # combo 4: SYN+FIN, one of the rejected illegal flag combinations


def _ruleset(*, tcpflags: bool, disposition: Disposition = Disposition.DROP) -> Ruleset:
    return Ruleset(
        zones=_ZONES,
        interfaces=(Interface(name="v_cli", tcpflags=tcpflags), Interface(name="v_srv")),
        policies=_POLICIES,
        settings=Settings(tcp_flags_disposition=disposition),
    )


def _forwarded(sb: nh.NetnsSandbox) -> bool:
    """True when a crafted SYN+FIN segment from the client reaches the server (was forwarded)."""
    sniff = subprocess.Popen(
        [nh.IP, "netns", "exec", _SERVER.name, nh.PY3, "-c", _SNIFF, _SERVER.peer,
         _CLIENT.host_ip4, "2.0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.3)  # let the sniffer bind before the first segment goes out
    sb.exec(
        _CLIENT.name,
        [nh.PY3, "-c", _SEND, _CLIENT.host_ip4, _SERVER.host_ip4, str(_SYN_FIN)],
    )
    out, _ = sniff.communicate(timeout=5)
    return out.strip() == "got"


@pytest.mark.netns
@_requires_netns
def test_tcpflags_drops_invalid_flags_but_control_passes() -> None:
    with nh.NetnsSandbox(_TOPO) as sb:
        # Control: with no tcpflags option the crafted SYN+FIN segment is forwarded to the server.
        sb.load(_ruleset(tcpflags=False))
        assert _forwarded(sb) is True
        # With tcpflags on the ingress interface the same segment is dropped in the forward chain.
        sb.load(_ruleset(tcpflags=True))
        assert _forwarded(sb) is False


@pytest.mark.netns
@_requires_netns
def test_tcpflags_reject_disposition_still_blocks() -> None:
    # A non-default disposition still terminates the invalid-flags segment (verdict becomes
    # `reject`, pinned byte-for-byte by the golden tests); it never reaches the server.
    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(_ruleset(tcpflags=True, disposition=Disposition.REJECT))
        assert _forwarded(sb) is False
