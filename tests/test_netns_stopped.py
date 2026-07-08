"""Netns behavioral proof of the stopped safe state (#213, epic #201, ADR-0021).

``stop`` loads a fail-closed ruleset admitting only declared admin-access traffic (stoppedrules)
plus the no-lockout baseline (loopback + established/related). This drives real TCP probes at the
firewall host (the router namespace) to prove: a packet matching a declared admin rule reaches the
host, a non-admin packet is dropped, and with zero admin rules the baseline still admits loopback
while dropping new non-admin traffic. The stopped ruleset loads through the harness ``generator``
seam (:func:`shorewallnf.generator.generate_stopped`). Gated on the ``netns`` marker + root, so it
skips cleanly in the hermetic tier and runs in the privileged netns CI tier (epics #77/#78).
"""

from __future__ import annotations

import pytest

from shorewallnf.generator import generate_stopped
from shorewallnf.ir import Family, Rule, Ruleset, Zone, ZoneMember
from tests import netns_harness as nh

# An admin client wired to the firewall host (the router namespace); RFC 5737 range, unique names
# so the sandbox cannot collide with other netns tests.
ADMIN = nh.Endpoint(
    name="snf213_admin", iface="v_adm", peer="p_adm", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
TOPO = nh.Topology(router="snf213_r", endpoints=(ADMIN,))
_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="admin", members=(ZoneMember(interface="v_adm", family=Family.BOTH),)),
)
_ADMIN_PORT = 22  # a declared admin rule opens this on the host
_BLOCKED_PORT = 8080  # no rule opens this — the fail-closed input policy must drop it

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _stopped(*rules: Rule) -> Ruleset:
    return Ruleset(zones=_ZONES, stopped_rules=rules)


@pytest.mark.netns
@_requires_netns
def test_stopped_state_admits_admin_and_drops_the_rest() -> None:
    # A declared admin rule (SSH from the admin zone to the firewall) reaches the host; a port no
    # rule opens is dropped by the fail-closed input policy.
    rs = _stopped(Rule(action="ACCEPT", source="admin", dest="fw", proto="tcp", dport="22"))
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(rs, generator=generate_stopped)
        with nh.listeners(sb, TOPO.router, (_ADMIN_PORT, _BLOCKED_PORT)):
            assert sb.connect(ADMIN.name, ADMIN.gateway4, _ADMIN_PORT) == "open"
            assert sb.connect(ADMIN.name, ADMIN.gateway4, _BLOCKED_PORT) == "filtered"


@pytest.mark.netns
@_requires_netns
def test_stopped_state_without_admin_rules_is_no_lockout_baseline() -> None:
    # Zero admin rules: the baseline still admits loopback on the host, but a new non-admin
    # connection from the client is dropped — no lockout, no open door.
    rs = _stopped()
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(rs, generator=generate_stopped)
        with nh.listeners(sb, TOPO.router, (_ADMIN_PORT,)):
            assert sb.connect(TOPO.router, "127.0.0.1", _ADMIN_PORT) == "open"
            assert sb.connect(ADMIN.name, ADMIN.gateway4, _ADMIN_PORT) == "filtered"
