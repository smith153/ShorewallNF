"""Built-in conntrack-helper registry (documented subset, ADR-0040).

A pure, immutable, name-keyed table of the standard conntrack helpers, each mapped to its
canonical L4 protocol, default port(s), and family capability (v4-only vs v6-capable,
ADR-0002), expressed as :class:`~shorewallnf.ir.HelperDef` values. The parser (#220) resolves
a ``conntrack`` row's helper name against this table; the generator (#221) gates emission on
the compile-time capability surface (:class:`~shorewallnf.ir.HelperCapabilities`). This module
is only the static data — it does no lookup, narrowing, or capability detection itself.

Only the helpers the reference config needs are listed (YAGNI); the mapping is enumerable so
an unknown name is detectable. Family capability follows the kernel helper: FTP/TFTP/SIP are
v6-capable; PPTP is IPv4-only (its GRE pairing has no IPv6 conntrack support).
"""

from collections.abc import Mapping
from types import MappingProxyType

from shorewallnf.ir import Family, HelperDef

# FTP control channel on TCP 21; the helper reads PORT/PASV and expects the data
# connection as RELATED. v6-capable.
_FTP = HelperDef(name="ftp", proto="tcp", ports=("21",), family_capability=Family.BOTH)

# TFTP request on UDP 69; the helper expects the RELATED data transfer. v6-capable.
_TFTP = HelperDef(name="tftp", proto="udp", ports=("69",), family_capability=Family.BOTH)

# SIP signalling on UDP 5060; the helper opens the RTP media flows as RELATED. v6-capable.
_SIP = HelperDef(name="sip", proto="udp", ports=("5060",), family_capability=Family.BOTH)

# PPTP control channel on TCP 1723, pairing the GRE tunnel. IPv4-only.
_PPTP = HelperDef(name="pptp", proto="tcp", ports=("1723",), family_capability=Family.IPV4)

BUILTIN_HELPERS: Mapping[str, HelperDef] = MappingProxyType(
    {h.name: h for h in (_FTP, _TFTP, _SIP, _PPTP)}
)
