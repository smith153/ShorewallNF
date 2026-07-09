"""Tests for the netns behavioral harness (task #115, epic #77).

The pure command-planning core (topology -> ``ip``/``nft`` argv, render reuse) is exercised
hermetically here — no root, no namespaces. The one behavioral assertion (a policy DROP blocks
a ping) is gated on :func:`netns_harness.netns_available` and skipped cleanly without privileges.
"""

from __future__ import annotations

from collections.abc import Sequence

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


def test_render_accepts_a_custom_generator() -> None:
    # The stopped safe state (#213) loads through the same seam via generate_stopped.
    from shorewallnf.generator import generate_stopped

    rs = Ruleset(zones=(Zone(name="fw", is_firewall=True),))
    assert nh.render(rs, generate_stopped) == generate_stopped(rs)
    assert nh.load_payload(rs, generate_stopped)["nftables"][1:] == generate_stopped(rs)["nftables"]


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
    # The pair is created under collision-proof temp names in the root ns, moved into place, then
    # renamed to the caller's names *inside* each namespace (never `ip link add v_cli` in root).
    tmp_r, tmp_e = "snfv0a", "snfv0b"
    assert ["ip", "link", "add", tmp_r, "type", "veth", "peer", "name", tmp_e] in cmds
    assert ["ip", "link", "set", tmp_r, "netns", "snf_r"] in cmds
    assert ["ip", "link", "set", tmp_e, "netns", "snf_client"] in cmds
    assert ["ip", "-n", "snf_r", "link", "set", tmp_r, "name", "v_cli"] in cmds
    assert ["ip", "-n", "snf_client", "link", "set", tmp_e, "name", "p_cli"] in cmds


def test_root_namespace_creation_never_uses_caller_device_names() -> None:
    # Regression (PR #270): a caller may name its router-side veth after a real device (e.g. `eth0`,
    # to match a fixture's `iifname`). Creating that name in the root ns collides with a host device
    # of the same name and hard-fails, so the harness must only ever touch caller names *inside* a
    # namespace (an `ip -n <ns> …` command), never in the root ns.
    ep = nh.Endpoint(
        name="ns_a", iface="eth0", peer="eth1", addr4="192.0.2.2/24", router4="192.0.2.1/24"
    )
    cmds = nh.setup_commands(nh.Topology(router="r", endpoints=(ep,)))
    for cmd in cmds:
        if "eth0" in cmd or "eth1" in cmd:
            assert cmd[:2] == ["ip", "-n"], f"caller device name used in root namespace: {cmd}"


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
    # `nodad` skips Duplicate Address Detection so the address is usable immediately rather than
    # transiently `tentative` — otherwise a lone `ping -6 -c 1 -W 1` races DAD and fails spuriously.
    assert ["ip", "-n", "r", "addr", "add", "2001:db8:3::1/64", "dev", "v6c", "nodad"] in cmds
    assert ["ip", "-n", "c6", "addr", "add", "2001:db8:3::2/64", "dev", "p6c", "nodad"] in cmds
    assert ["ip", "-6", "-n", "c6", "route", "add", "default", "via", "2001:db8:3::1"] in cmds


def test_v4_only_endpoint_adds_no_v6_commands() -> None:
    cmds = nh.setup_commands(TOPO)
    assert not any("2001:db8" in tok or tok == "-6" for cmd in cmds for tok in cmd)


def test_teardown_deletes_every_namespace() -> None:
    # Namespaces free the veths moved *into* them; the trailing root-ns `link del snfv{i}a`
    # per endpoint index sweeps any temp veth still stranded in the root ns from a partial
    # setup (a veth deletes as a unit, so one end per index suffices) — issue #279.
    assert nh.teardown_commands(TOPO) == [
        ["ip", "netns", "del", "snf_r"],
        ["ip", "netns", "del", "snf_client"],
        ["ip", "netns", "del", "snf_server"],
        ["ip", "link", "del", "snfv0a"],
        ["ip", "link", "del", "snfv1a"],
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


# ---- probe command planning (pure, root-free) -------------------------------------------


def test_connect_command_shape() -> None:
    cmd = nh.connect_command("snf_client", "198.51.100.2", 80, timeout=1.0)
    assert cmd[:6] == ["ip", "netns", "exec", "snf_client", "python3", "-c"]
    assert cmd[6] == nh._CONNECT
    assert cmd[7:] == ["198.51.100.2", "80", "1.0"]


def test_connect_command_default_timeout() -> None:
    assert nh.connect_command("ns", "127.0.0.1", 22)[-3:] == ["127.0.0.1", "22", "1.0"]


def test_listen_command_shape() -> None:
    cmd = nh.listen_command("snf_server", 443)
    assert cmd[:6] == ["ip", "netns", "exec", "snf_server", "python3", "-c"]
    assert cmd[6] == nh._LISTEN
    assert cmd[7:] == ["443"]


def test_echo_listen_command_shape() -> None:
    cmd = nh.echo_listen_command("snf_a", 9237, "A")
    assert cmd[:6] == ["ip", "netns", "exec", "snf_a", "python3", "-c"]
    assert cmd[6] == nh._ECHO_LISTEN
    assert cmd[7:] == ["9237", "A"]


def test_probe_command_carries_mark_and_timeout() -> None:
    cmd = nh.probe_command("snf_r", "203.0.113.100", 9237, mark=1, timeout=2.0)
    assert cmd[:6] == ["ip", "netns", "exec", "snf_r", "python3", "-c"]
    assert cmd[6] == nh._MARKPROBE
    assert cmd[7:] == ["203.0.113.100", "9237", "1", "2.0"]


def test_probe_command_defaults_to_unmarked() -> None:
    assert nh.probe_command("ns", "127.0.0.1", 9239)[7:] == ["127.0.0.1", "9239", "0", "1.0"]


# ---- teardown-on-failure (hermetic, root-free via _run injection) -----------------------


def test_enter_tears_down_when_setup_fails_midway(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mid-setup command failure must tear down what was created before re-raising, so a
    partially-built sandbox never leaks namespaces into the next run (issue #273). Proven without
    root by injecting a failing ``_run``: assert the original error re-raises and every
    ``teardown_commands`` argv is invoked afterward."""
    setup = nh.setup_commands(TOPO)
    fail_at = setup[2]  # a mid-setup command, after some namespaces already exist
    calls: list[list[str]] = []

    def fake_run(cmd: Sequence[str], *, check: bool = True, stdin_text: str | None = None) -> None:
        calls.append(list(cmd))
        if list(cmd) == fail_at:
            raise RuntimeError("boom")

    monkeypatch.setattr(nh, "_run", fake_run)

    with pytest.raises(RuntimeError, match="boom"):
        with nh.NetnsSandbox(TOPO):
            pass

    failure_index = calls.index(fail_at)
    teardown = nh.teardown_commands(TOPO)
    # Every teardown argv ran, and each ran only after the setup failure.
    for cmd in teardown:
        assert cmd in calls[failure_index + 1 :], f"teardown missing after failure: {cmd}"


def test_enter_deletes_temp_veth_when_first_netns_move_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If setup dies right after `ip link add snfv0a … peer snfv0b` but before the FIRST
    `link set snfv0a netns <router>` move, both temp ends orphan in the root ns; teardown's
    trailing `link del snfv0a` must sweep them so a re-run doesn't hard-fail on `File exists`
    (issue #279). Proven root-free by failing that first move via injected ``_run``."""
    first_move = ["ip", "link", "set", "snfv0a", "netns", TOPO.router]
    assert first_move in nh.setup_commands(TOPO)  # guards against a planner rename
    calls: list[list[str]] = []

    def fake_run(cmd: Sequence[str], *, check: bool = True, stdin_text: str | None = None) -> None:
        calls.append(list(cmd))
        if list(cmd) == first_move:
            raise RuntimeError("boom")

    monkeypatch.setattr(nh, "_run", fake_run)

    with pytest.raises(RuntimeError, match="boom"):
        with nh.NetnsSandbox(TOPO):
            pass

    failure_index = calls.index(first_move)
    assert ["ip", "link", "del", "snfv0a"] in calls[failure_index + 1 :]


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
