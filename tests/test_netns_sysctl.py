"""Netns behavioral proof of the applier's kernel-sysctl seam (#322, epic #309, ADR-0062).

``apply_sysctls`` is the applier's first kernel mutation outside nftables: ``IP_FORWARDING``
On/Off drives the forwarding sysctls, and ``Keep`` (the all-defaults / absent-file case) leaves
the pre-existing value untouched. A network namespace has its own isolated ``net.*`` sysctls, so
this runs the production ``apply_sysctls`` inside a throwaway router namespace and reads the
forwarding sysctls back to prove the observable effect. Gated on the ``netns`` marker + root, so
it skips cleanly in the hermetic tier and runs in the privileged netns CI tier (epics #77/#78).
"""

from __future__ import annotations

import sys

import pytest

from tests import netns_harness as nh

# A router namespace with no endpoints — the sysctl seam mutates the router's own net namespace,
# no traffic path is needed. The harness `setup_commands` pre-sets forwarding to 1 on the router.
TOPO = nh.Topology(router="snf322_r", endpoints=())

_FORWARD_KEYS = ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")

# Run the production applier's sysctl step inside the router namespace: build a Settings with the
# given IP_FORWARDING member (argv[1]) and apply it. All-Keep (argv[1]="KEEP") is a no-op.
_APPLY_SYSCTLS = (
    "import sys; from shorewallnf.applier import apply_sysctls; "
    "from shorewallnf.ir import Settings, OnOffKeep; "
    "apply_sysctls(Settings(ip_forwarding=OnOffKeep[sys.argv[1]]))"
)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _apply(sb: nh.NetnsSandbox, member: str) -> None:
    sb.exec(TOPO.router, [sys.executable, "-c", _APPLY_SYSCTLS, member])


def _read(sb: nh.NetnsSandbox, key: str) -> str:
    return sb.exec(TOPO.router, ["sysctl", "-n", key]).stdout.strip()


@pytest.mark.netns
@_requires_netns
def test_ip_forwarding_off_then_on_observably_sets_the_forwarding_sysctls() -> None:
    with nh.NetnsSandbox(TOPO) as sb:
        _apply(sb, "OFF")
        assert [_read(sb, key) for key in _FORWARD_KEYS] == ["0", "0"]
        _apply(sb, "ON")
        assert [_read(sb, key) for key in _FORWARD_KEYS] == ["1", "1"]


@pytest.mark.netns
@_requires_netns
def test_ip_forwarding_keep_leaves_the_pre_existing_value_untouched() -> None:
    with nh.NetnsSandbox(TOPO) as sb:
        # Pin a known pre-existing value, then apply all-Keep settings: the value must survive.
        _apply(sb, "OFF")
        assert [_read(sb, key) for key in _FORWARD_KEYS] == ["0", "0"]
        _apply(sb, "KEEP")
        assert [_read(sb, key) for key in _FORWARD_KEYS] == ["0", "0"]
