"""Netns behavioral proof that a helper-dependent data connection is admitted only via the loaded
conntrack helper (task #223, epic #200; ADR-0040/0041 helper gating, ADR-0005 stateful base).

Builds on #222's committed conntrack fixture. That fixture attaches the active-FTP conntrack helper
to the FTP control channel (``net -> loc:198.51.100.10`` tcp 21) under a default-drop policy. This
drives the whole path on real traffic: a client and an FTP server wired to a router, the compiled
ruleset loaded into the router, and a **passive-FTP** exchange over the control channel. The server
advertises its data channel in an RFC 959 ``227 Entering Passive Mode`` line — the exact payload
``nf_conntrack_ftp`` parses to register the data connection as a conntrack *expectation*. The data
port is a high port no ACCEPT rule covers, so under default-drop it is reachable only if the kernel
marks it ``RELATED`` — which happens only when the ftp ``ct helper`` is attached.

Teeth come from compiling the **same** fixture twice: a capability surface that provides ``ftp``
(the helper is attached) vs one that does not (``ftp`` skipped, ADR-0041). The only delta between
the two loaded rulesets is the ftp ``ct helper`` object + its assignment rule, so the difference in
outcome — data connection admitted vs dropped — is attributable to the helper alone.

Gated on the ``netns`` marker, root + ip/nft (:func:`netns_harness.netns_available`), and the
``nf_conntrack_ftp`` kernel module: a missing capability skips cleanly, it never fails, keeping the
hermetic tier green without privileges (epics #77/#78).
"""

from __future__ import annotations

import subprocess
import time
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from shorewallnf import cli
from shorewallnf.generator import generate
from shorewallnf.ir import HelperCapabilities
from shorewallnf.parser import parse_config
from tests import netns_harness as nh

# The committed conntrack fixture from #222. Its `net`/`loc` interfaces are eth0/eth1 and it narrows
# the ftp helper to loc:198.51.100.10, so the topology below names its router-side veths eth0/eth1
# and puts the server on 198.51.100.10 to line the generated matches up with the sandbox.
CONNTRACK_FIXTURE = Path(__file__).parent / "fixtures" / "conntrack_compile_dir"

CLIENT = nh.Endpoint(
    name="snf223_cli", iface="eth0", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
SERVER = nh.Endpoint(
    name="snf223_srv", iface="eth1", peer="p_srv",
    addr4="198.51.100.10/24", router4="198.51.100.1/24",
)
TOPO = nh.Topology(router="snf223_r", endpoints=(CLIENT, SERVER))

_CTRL_PORT = 21
# A high data port outside every ACCEPT rule (the fixture opens 21/22/69/1723), so the data channel
# is reachable only when conntrack marks it RELATED via the ftp helper's expectation.
_DATA_PORT = 40021
_TAG = "DATA"

# Two capability surfaces over the SAME fixture (ADR-0040): the delta is exactly the ftp helper.
_CAPS_ON = HelperCapabilities(available=frozenset({"ftp", "tftp", "pptp"}))
_CAPS_OFF = HelperCapabilities(available=frozenset({"tftp", "pptp"}))  # ftp unattached

# Parsed once at import — pure, hermetic-safe (no root). Only the render capabilities differ.
_RULESET = parse_config(cli.preprocess(CONNTRACK_FIXTURE))


def _ftp_helper_available() -> bool:
    """netns tier is available AND the ``nf_conntrack_ftp`` helper module can be loaded.

    Guarded by :func:`netns_harness.netns_available` (root) first, so the hermetic tier never shells
    out to ``modprobe`` — the module gate stays consistent with the tier's skip-not-fail contract.
    """
    if not nh.netns_available():
        return False
    subprocess.run(["modprobe", "nf_conntrack_ftp"], capture_output=True, check=False)
    return Path("/sys/module/nf_conntrack_ftp").exists()


_requires_ftp = pytest.mark.skipif(
    not _ftp_helper_available(),
    reason="netns tier needs root + ip/nft + nf_conntrack_ftp (epics #77/#78)",
)

# A minimal passive-FTP control server: greet, read the client's PASV, then advertise its own data
# address/port in an RFC 959 `227 Entering Passive Mode` line — the payload nf_conntrack_ftp parses
# to register the data connection as an expectation — and serve one identity tag over that channel.
# Each connection is handled defensively so a startup probe cannot wedge the accept loop.
_FTP_SERVER = (
    "import socket,sys\n"
    "host,ctrl,data,tag=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),sys.argv[4]\n"
    "d=socket.socket(); d.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "d.bind(('0.0.0.0',data)); d.listen(1); d.settimeout(5)\n"
    "c=socket.socket(); c.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "c.bind(('0.0.0.0',ctrl)); c.listen(1)\n"
    "p1,p2=divmod(data,256)\n"
    "pasv=('227 Entering Passive Mode (%s,%d,%d).\\r\\n'%(host.replace('.',','),p1,p2)).encode()\n"
    "while True:\n"
    "    try:\n"
    "        conn,_=c.accept()\n"
    "    except OSError:\n"
    "        break\n"
    "    try:\n"
    "        conn.sendall(b'220 ready\\r\\n')\n"
    "        conn.recv(64)\n"
    "        conn.sendall(pasv)\n"
    "        dc,_=d.accept()\n"
    "        dc.sendall(tag.encode()); dc.close()\n"
    "    except OSError:\n"
    "        pass\n"
    "    finally:\n"
    "        conn.close()\n"
)

# The passive-FTP client: open the control channel, drive PASV, parse the advertised data
# address/port, and dial it. Prints the tag the data listener echoes — or `filtered` when the data
# SYN is dropped (the helper-off case), `control-failed` when the server isn't accepting yet.
_FTP_CLIENT = (
    "import socket,sys,re\n"
    "host,ctrl,timeout=sys.argv[1],int(sys.argv[2]),float(sys.argv[3])\n"
    "c=socket.socket(); c.settimeout(timeout)\n"
    "try:\n"
    "    c.connect((host,ctrl)); c.recv(64); c.sendall(b'PASV\\r\\n'); resp=c.recv(128).decode()\n"
    "except OSError:\n"
    "    print('control-failed'); sys.exit()\n"
    "m=re.search(r'\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)',resp)\n"
    "if not m:\n"
    "    print('no-pasv'); sys.exit()\n"
    "o=[int(x) for x in m.groups()]\n"
    "addr='.'.join(str(n) for n in o[:4]); port=o[4]*256+o[5]\n"
    "s=socket.socket(); s.settimeout(timeout)\n"
    "try:\n"
    "    s.connect((addr,port)); print(s.recv(16).decode() or 'empty')\n"
    "except ConnectionRefusedError:\n"
    "    print('refused')\n"
    "except OSError:\n"
    "    print('filtered')\n"
)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


@contextmanager
def _ftp_server(ns: str, host: str, ctrl_port: int, data_port: int, tag: str) -> Iterator[None]:
    """Run the passive-FTP control/data server in ``ns`` for the duration of the block."""
    proc = subprocess.Popen(
        [nh.IP, "netns", "exec", ns, nh.PY3, "-c", _FTP_SERVER,
         host, str(ctrl_port), str(data_port), tag]
    )
    try:
        yield
    finally:
        proc.terminate()
        proc.wait()


def _run_ftp_client(
    sb: nh.NetnsSandbox, src_ns: str, host: str, ctrl_port: int,
    *, timeout: float = 1.0, attempts: int = 30,
) -> str:
    """Drive the passive-FTP exchange from ``src_ns``, retrying only while the server isn't yet
    accepting (``control-failed``); return the data-channel outcome (tag / ``filtered``)."""
    argv = [nh.PY3, "-c", _FTP_CLIENT, host, str(ctrl_port), str(timeout)]
    for _ in range(attempts):
        result = sb.exec(src_ns, argv, check=False).stdout.strip()
        if result != "control-failed":
            return result
        time.sleep(0.1)
    return "control-failed"


def _data_channel_outcome(caps: HelperCapabilities) -> str:
    """Compile the fixture under ``caps``, load it into a fresh sandbox (isolated conntrack), and
    return whether the passive-FTP data channel is admitted (``_TAG``) or dropped (``filtered``)."""
    with nh.NetnsSandbox(TOPO) as sb:
        # Pin off kernel auto-helper so the ftp helper attaches only via the ADR-0041 assignment
        # rule — otherwise the port-21 auto-assign could track the data channel without it.
        sb.exec(TOPO.router, ["sysctl", "-qw", "net.netfilter.nf_conntrack_helper=0"], check=False)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # the ftp-off surface skips ftp with a UserWarning
            sb.load(_RULESET, generator=lambda rs: generate(rs, caps))
        with _ftp_server(SERVER.name, SERVER.host_ip4, _CTRL_PORT, _DATA_PORT, _TAG):
            return _run_ftp_client(sb, CLIENT.name, SERVER.host_ip4, _CTRL_PORT)


@pytest.mark.netns
@_requires_netns
@_requires_ftp
def test_ftp_data_connection_admitted_only_via_the_loaded_helper() -> None:
    """With the ftp helper attached, the passive-FTP data connection is tracked RELATED and
    admitted; with the same fixture compiled ftp-off, the identical data connection is dropped
    under the default-drop policy. The helper is load-bearing, not incidental."""
    assert _data_channel_outcome(_CAPS_ON) == _TAG
    assert _data_channel_outcome(_CAPS_OFF) == "filtered"
