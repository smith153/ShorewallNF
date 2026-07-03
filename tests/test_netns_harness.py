"""Tests for the netns behavioral harness (task #115, epic #77).

The pure command-planning core (topology -> ``ip``/``nft`` argv, render reuse) is exercised
hermetically here — no root, no namespaces. The one behavioral assertion (a policy DROP blocks
a ping) is gated on :func:`netns_harness.netns_available` and skipped cleanly without privileges.
"""

from __future__ import annotations

import pytest

from shorewallnf.generator import generate
from shorewallnf.ir import Family, Policy, Ruleset, Zone, ZoneMember
from tests import netns_harness as nh

CLIENT = nh.Endpoint(
    name="snf_client", iface="v_cli", peer="p_cli", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
SERVER = nh.Endpoint(
    name="snf_server",
    iface="v_srv",
    peer="p_srv",
    addr4="198.51.100.2/24",
    router4="198.51.100.1/24",
)
TOPO = nh.Topology(router="snf_r", endpoints=(CLIENT, SERVER))


# ---- availability predicate -------------------------------------------------------------


def test_netns_available_returns_bool() -> None:
    assert isinstance(nh.netns_available(), bool)


def test_have_binaries_false_when_missing() -> None:
    assert nh._have_binaries(["definitely-not-a-real-binary-xyz-42"]) is False


def test_have_binaries_true_for_empty() -> None:
    assert nh._have_binaries([]) is True


# ---- render reuse (AC: no re-implementation of IR -> JSON) ------------------------------


def test_render_reuses_generator() -> None:
    rs = Ruleset(policies=(Policy(source="all", dest="all", action="DROP"),))
    assert nh.render(rs) == generate(rs)


def test_load_payload_flushes_then_renders() -> None:
    rs = Ruleset(policies=(Policy(source="all", dest="all", action="DROP"),))
    payload = nh.load_payload(rs)
    assert payload["nftables"][0] == {"flush": {"ruleset": None}}
    assert payload["nftables"][1:] == generate(rs)["nftables"]


# ---- topology -> command planning -------------------------------------------------------


def test_namespaces_are_router_then_endpoints() -> None:
    assert TOPO.namespaces == ("snf_r", "snf_client", "snf_server")


def test_endpoint_derives_bare_addresses() -> None:
    assert CLIENT.host_ip4 == "192.0.2.2"
    assert CLIENT.gateway4 == "192.0.2.1"


def test_setup_creates_namespaces_first() -> None:
    cmds = nh.setup_commands(TOPO)
    assert cmds[0] == ["ip", "netns", "add", "snf_r"]
    for ns in TOPO.namespaces:
        assert ["ip", "netns", "add", ns] in cmds


def test_setup_creates_and_moves_veth_pairs() -> None:
    cmds = nh.setup_commands(TOPO)
    assert ["ip", "link", "add", "v_cli", "type", "veth", "peer", "name", "p_cli"] in cmds
    assert ["ip", "link", "set", "v_cli", "netns", "snf_r"] in cmds
    assert ["ip", "link", "set", "p_cli", "netns", "snf_client"] in cmds


def test_setup_assigns_addresses_and_default_route() -> None:
    cmds = nh.setup_commands(TOPO)
    assert ["ip", "-n", "snf_r", "addr", "add", "192.0.2.1/24", "dev", "v_cli"] in cmds
    assert ["ip", "-n", "snf_client", "addr", "add", "192.0.2.2/24", "dev", "p_cli"] in cmds
    assert ["ip", "-n", "snf_client", "route", "add", "default", "via", "192.0.2.1"] in cmds


def test_setup_enables_forwarding_on_router() -> None:
    cmds = nh.setup_commands(TOPO)
    assert ["ip", "netns", "exec", "snf_r", "sysctl", "-qw", "net.ipv4.ip_forward=1"] in cmds
    assert (
        ["ip", "netns", "exec", "snf_r", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"] in cmds
    )


def test_dual_stack_endpoint_adds_v6_address_and_route() -> None:
    ep = nh.Endpoint(
        name="c6",
        iface="v6c",
        peer="p6c",
        addr4="203.0.113.2/24",
        router4="203.0.113.1/24",
        addr6="2001:db8:3::2/64",
        router6="2001:db8:3::1/64",
    )
    cmds = nh.setup_commands(nh.Topology(router="r", endpoints=(ep,)))
    assert ["ip", "-n", "r", "addr", "add", "2001:db8:3::1/64", "dev", "v6c"] in cmds
    assert ["ip", "-n", "c6", "addr", "add", "2001:db8:3::2/64", "dev", "p6c"] in cmds
    assert ["ip", "-6", "-n", "c6", "route", "add", "default", "via", "2001:db8:3::1"] in cmds


def test_v4_only_endpoint_adds_no_v6_commands() -> None:
    cmds = nh.setup_commands(TOPO)
    assert not any("2001:db8" in tok or tok == "-6" for cmd in cmds for tok in cmd)


def test_teardown_deletes_every_namespace() -> None:
    assert nh.teardown_commands(TOPO) == [
        ["ip", "netns", "del", "snf_r"],
        ["ip", "netns", "del", "snf_client"],
        ["ip", "netns", "del", "snf_server"],
    ]


def test_load_command_reads_json_from_stdin() -> None:
    assert nh.load_command("snf_r") == ["ip", "netns", "exec", "snf_r", "nft", "-j", "-f", "-"]


def test_apply_command_runs_real_applier_in_router() -> None:
    cmd = nh.apply_command("snf_r", python="/usr/bin/python3")
    assert cmd[:5] == ["ip", "netns", "exec", "snf_r", "/usr/bin/python3"]
    assert cmd[5] == "-c"
    # Faithful to the real apply path: it calls apply_ruleset, not a flush-ruleset shortcut.
    assert "apply_ruleset" in cmd[6]
    assert "flush" not in cmd[6]


def test_ping_command_v4() -> None:
    assert nh.ping_command("snf_client", "198.51.100.2", count=2) == [
        "ip", "netns", "exec", "snf_client", "ping", "-4", "-c", "2", "-W", "1", "198.51.100.2",
    ]


def test_ping_command_v6() -> None:
    cmd = nh.ping_command("c6", "2001:db8:3::2", family=6)
    assert cmd[4:6] == ["ping", "-6"]
    assert cmd[-1] == "2001:db8:3::2"


# ---- behavioral tier (gated: root + ip/nft) ---------------------------------------------

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="client", members=(ZoneMember(interface="v_cli", family=Family.BOTH),)),
    Zone(name="server", members=(ZoneMember(interface="v_srv", family=Family.BOTH),)),
)


@pytest.mark.netns
@pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)
def test_forward_drop_blocks_ping() -> None:
    accept = Ruleset(
        zones=_ZONES, policies=(Policy(source="client", dest="server", action="ACCEPT"),)
    )
    drop = Ruleset(
        zones=_ZONES, policies=(Policy(source="client", dest="server", action="DROP"),)
    )
    with nh.NetnsSandbox(TOPO) as sb:
        sb.load(accept)
        assert sb.ping(CLIENT.name, SERVER.host_ip4), "ACCEPT policy should let the ping through"
        sb.load(drop)
        assert not sb.ping(CLIENT.name, SERVER.host_ip4), "DROP policy should block the ping"


# A co-resident table ShorewallNF must not own or clobber (added out-of-band below).
_COEXIST_TABLE = ("nft", "add", "table", "inet", "coexist_probe")


@pytest.mark.netns
@pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)
def test_apply_real_path_packet_path_reapply_and_coresident() -> None:
    """The production apply path (ADR-0010 scoped replace, not ``flush ruleset``): a real apply
    controls the packet path, a re-apply atomically swaps it with no teardown gap, and a
    co-resident non-ShorewallNF table survives the apply."""
    accept = Ruleset(
        zones=_ZONES, policies=(Policy(source="client", dest="server", action="ACCEPT"),)
    )
    drop = Ruleset(
        zones=_ZONES, policies=(Policy(source="client", dest="server", action="DROP"),)
    )
    with nh.NetnsSandbox(TOPO) as sb:
        # A non-ShorewallNF table pre-existing in the router netns must survive every apply.
        sb.exec(sb.topo.router, _COEXIST_TABLE)

        # First apply via the real applier: ACCEPT opens the forward path.
        sb.apply(accept)
        assert sb.ping(CLIENT.name, SERVER.host_ip4), "ACCEPT policy should let the ping through"

        # Re-apply atomically replaces the previous ShorewallNF ruleset with the new packet path.
        sb.apply(drop)
        assert not sb.ping(CLIENT.name, SERVER.host_ip4), "DROP re-apply should block the ping"

        # The co-resident table is untouched by the scoped replace (no `flush ruleset`).
        survived = sb.exec(sb.topo.router, ("nft", "list", "table", "inet", "coexist_probe"))
        assert survived.returncode == 0, "co-resident table must survive a ShorewallNF apply"
