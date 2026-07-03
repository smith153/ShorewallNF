"""Built-in macro / custom-action registry (documented subset, ADR-0020).

A pure, immutable, name-keyed mapping of the standard macros and actions the
reference config depends on, expressed as :class:`~shorewallnf.ir.MacroDef`
verdict templates. The resolver (#184) consults this alongside parsed
site-defined ``action.<Name>`` definitions (site defs winning per ADR-0020 §6);
this module does no lookup, narrowing, or override precedence itself — it is only
the name-addressable built-in half of that registry.

Every body line is a built-in verdict (``ACCEPT``/``DROP``/``REJECT``), optionally
narrowed by ``proto``/``dport``/``sport``/``family`` — the subset epic #176 scopes.
Capabilities are described abstractly; no reference-config values appear here.
"""

from collections.abc import Mapping
from types import MappingProxyType

from shorewallnf.ir import MacroDef, MacroRule

# A port-group macro: accept inbound HTTP and HTTPS.
_WEB = MacroDef(
    name="Web",
    body=(
        MacroRule(action="ACCEPT", proto="tcp", dport="80"),
        MacroRule(action="ACCEPT", proto="tcp", dport="443"),
    ),
)

# A drop-noise action: silently DROP SMB/NetBIOS chatter (UDP 137-139/445,
# TCP 139/445) so it never reaches a policy or logs.
_DROP_SMB = MacroDef(
    name="DropSmb",
    body=(
        MacroRule(action="DROP", proto="udp", dport="137:139"),
        MacroRule(action="DROP", proto="udp", dport="445"),
        MacroRule(action="DROP", proto="tcp", dport="139"),
        MacroRule(action="DROP", proto="tcp", dport="445"),
    ),
)

BUILTIN_MACROS: Mapping[str, MacroDef] = MappingProxyType(
    {m.name: m for m in (_WEB, _DROP_SMB)}
)
