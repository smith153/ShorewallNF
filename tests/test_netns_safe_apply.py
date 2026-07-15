"""Netns behavioral proof of lockout-recovery auto-revert under ``try`` (#440, epic #405).

The safe-apply primitive (:func:`shorewallnf.applier.safe_apply`, #437) snapshots the running
ruleset, applies a candidate, and — after a timeout — reverts to the pre-``try`` state. The
hermetic tests for #437 stub the nft seams; this proves the recovery on a *real* packet path: a
candidate that severs the operator's control path auto-reverts and **restores connectivity** with
no operator action.

Topology: one router (firewall host) namespace + one client endpoint namespace, wired by the
existing :mod:`tests.netns_harness`. The "control path" is a TCP service on the firewall host,
observed with the harness TCP ``connect`` probe (``open``/``filtered``), never ``ping`` — so the
test needs no binary beyond ``python3``/``ip``/``nft``. ``safe_apply`` shells to ``nft`` in the
*current* netns, so it is driven inside the router namespace via ``ip netns exec … python3 -c …``
(mirroring :data:`tests.netns_harness._APPLY_RUNNER`) with an explicit temp ``snapshot_path`` —
never :data:`shorewallnf.applier.DEFAULT_RULESET_PATH`.

Gated on the ``netns`` marker + root, so it skips cleanly in the hermetic tier and runs in the
privileged netns CI tier (epics #77/#78). RFC 5737 documentation ranges only.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from shorewallnf.generator import generate_stopped
from shorewallnf.ir import Family, Policy, Rule, Ruleset, Zone, ZoneMember
from tests import netns_harness as nh

# Unique per-test names so the sandbox cannot collide with sibling netns tests; RFC 5737 range.
_CLIENT = nh.Endpoint(
    name="snf440_c", iface="v_c440", peer="p_c440", addr4="192.0.2.2/24", router4="192.0.2.1/24"
)
_TOPO = nh.Topology(router="snf440_r", endpoints=(_CLIENT,))
_ROUTER_IP = _CLIENT.gateway4  # the firewall host address the client probes for the control path

_ZONES = (
    Zone(name="fw", is_firewall=True),
    Zone(name="client", members=(ZoneMember(interface="v_c440", family=Family.BOTH),)),
)

_CONTROL_PORT = 9440  # the operator control path: a TCP service on the firewall host

# Good (running) ruleset: admits the client -> fw control port, drops everything else. This is the
# state safe_apply snapshots via list_ruleset() and must restore on revert.
_GOOD = Ruleset(
    zones=_ZONES,
    rules=(
        Rule(action="ACCEPT", source="client", dest="fw", proto="tcp", dport=str(_CONTROL_PORT)),
    ),
    policies=(Policy(source="client", dest="fw", action="DROP"),),
)
# Candidate (bad) ruleset: a client -> fw DROP policy with no admit rule — the lockout.
_CANDIDATE = Ruleset(zones=_ZONES, policies=(Policy(source="client", dest="fw", action="DROP"),))
# The fail-closed safe state safe_apply reverts to only if a restore fails (never on these paths).
_STOPPED = Ruleset(zones=_ZONES)

# Real short revert window: long enough to observe the live candidate state before the revert fires,
# short enough to keep the test quick.
_TIMEOUT = 4

# Runs the real safe-apply primitive inside the router netns: read the candidate/stopped rulesets
# from files, then snapshot -> apply -> wait(timeout) -> revert, writing the pre-try snapshot to an
# explicit path (never DEFAULT_RULESET_PATH). Mirrors netns_harness._APPLY_RUNNER.
_SAFE_APPLY_RUNNER = (
    "import sys, json\n"
    "from pathlib import Path\n"
    "from shorewallnf.applier import safe_apply\n"
    "from shorewallnf.errors import ShorewallNFError\n"
    "candidate = json.loads(Path(sys.argv[1]).read_text())\n"
    "stopped = json.loads(Path(sys.argv[2]).read_text())\n"
    "window, snapshot = int(sys.argv[3]), Path(sys.argv[4])\n"
    "try:\n"
    "    safe_apply(candidate, stopped, timeout=window, snapshot_path=snapshot)\n"
    "except ShorewallNFError as err:\n"  # mirrors cli.main's single catch: one clear error, rc 1
    "    print(f'error: {err}', file=sys.stderr)\n"
    "    sys.exit(1)\n"
)

_requires_netns = pytest.mark.skipif(
    not nh.netns_available(), reason="netns behavioral tier needs root + ip/nft (epics #77/#78)"
)


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload))
    return path


def _safe_apply_argv(
    candidate: Path, stopped: Path, snapshot: Path, timeout: int = _TIMEOUT
) -> list[str]:
    """The ``ip netns exec <router> python3 -c …`` argv that drives safe_apply in the router ns.

    ``ip netns exec`` ``execvp``\\ s the command rather than forking it, so the spawned pid *is* the
    python process — which is what lets the signal tests below signal ``safe_apply`` directly.
    """
    return [
        nh.IP, "netns", "exec", _TOPO.router, sys.executable, "-c", _SAFE_APPLY_RUNNER,
        str(candidate), str(stopped), str(timeout), str(snapshot),
    ]


def _poll_connect(sb: nh.NetnsSandbox, port: int, expect: str, *, attempts: int = 100) -> None:
    """Bounded poll (mirrors :func:`tests.netns_harness._await`) until the client's control-path
    probe reads ``expect``. Short per-probe timeout so a filtered (silently dropped) SYN resolves
    fast; the ceiling only bounds a genuine failure."""
    for _ in range(attempts):
        if sb.connect(_CLIENT.name, _ROUTER_IP, port, timeout=0.3) == expect:
            return
        time.sleep(0.1)
    raise AssertionError(f"control path never reached {expect!r} on {_ROUTER_IP}:{port}")


def _owned_tables_present(sb: nh.NetnsSandbox) -> bool:
    """True when a ShorewallNF-owned table is live in the router ns (the candidate is loaded)."""
    out = sb.exec(_TOPO.router, [nh.NFT, "list", "ruleset"], check=False).stdout
    return "table inet filter" in out


def _poll_tables(sb: nh.NetnsSandbox, *, present: bool, attempts: int = 100) -> None:
    for _ in range(attempts):
        if _owned_tables_present(sb) is present:
            return
        time.sleep(0.1)
    raise AssertionError(f"router ruleset owned-table presence never became {present}")


@pytest.mark.netns
@_requires_netns
def test_try_lockout_auto_reverts_and_restores_control_path(tmp_path: Path) -> None:
    """A candidate that severs the client -> fw control path auto-reverts after the timeout: the
    control path is open before, filtered while the candidate is live, and open again after the
    revert — the pre-``try`` snapshot is restored with no operator action."""
    candidate = _write_json(tmp_path / "candidate.json", nh.render(_CANDIDATE))
    stopped = _write_json(
        tmp_path / "stopped.json", nh.render(_STOPPED, generator=generate_stopped)
    )
    snapshot = tmp_path / "pre-try-snapshot.json"  # explicit temp path, never DEFAULT_RULESET_PATH

    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(_GOOD)  # the running ruleset safe_apply will snapshot and restore
        with nh.listeners(sb, _TOPO.router, (_CONTROL_PORT,)):
            # (1) before: the control path is open.
            assert sb.connect(_CLIENT.name, _ROUTER_IP, _CONTROL_PORT) == "open"

            proc = subprocess.Popen(_safe_apply_argv(candidate, stopped, snapshot))
            try:
                # (2) while the candidate is live (after apply, before revert): lockout reproduced.
                _poll_connect(sb, _CONTROL_PORT, "filtered")
                proc.wait()  # the revert fires when the timeout window elapses
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait()
            assert proc.returncode == 0

            # (3) after the timeout-driven revert: connectivity is auto-restored.
            _poll_connect(sb, _CONTROL_PORT, "open")

    assert not snapshot.exists() or snapshot.read_text()  # snapshot lived under tmp_path only


@pytest.mark.netns
@_requires_netns
def test_try_from_nothing_running_reverts_to_a_cleared_ruleset(tmp_path: Path) -> None:
    """From an empty/cleared router netns, a candidate applied under ``try`` is live during the
    window and the ruleset is empty/cleared after the revert — no lockout, no stale ruleset."""
    candidate = _write_json(tmp_path / "candidate.json", nh.render(_CANDIDATE))
    stopped = _write_json(
        tmp_path / "stopped.json", nh.render(_STOPPED, generator=generate_stopped)
    )
    snapshot = tmp_path / "pre-try-snapshot.json"

    with nh.NetnsSandbox(_TOPO) as sb:
        # Fresh netns: nothing running (no owned tables), so the revert target is clear.
        assert not _owned_tables_present(sb)

        proc = subprocess.Popen(_safe_apply_argv(candidate, stopped, snapshot))
        try:
            _poll_tables(sb, present=True)  # the candidate is live during the window
            proc.wait()
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()
        assert proc.returncode == 0

        # After the revert: the ruleset is cleared (empty), not left carrying the candidate.
        _poll_tables(sb, present=False)


# --- #450: a signalled death mid-window still reverts, on a real packet path -------------------
#
# The lockout the safe-apply verbs exist for kills more than the session: sshd SIGHUPs the process
# group as it tears the severed session down. The revert used to be plain foreground control flow
# after the wait seam, so the signal killed it too and the candidate that caused the lockout stayed
# loaded permanently. These prove the trapped signal now reverts on real traffic.
#
# The window is deliberately far longer than the test takes, so a passing run cannot be the timeout
# quietly doing the work — only the signal can end this window.
_SIGNAL_WINDOW = 600


@pytest.mark.netns
@_requires_netns
@pytest.mark.parametrize("signum", [signal.SIGHUP, signal.SIGTERM, signal.SIGINT],
                         ids=lambda s: s.name)
def test_try_reverts_and_restores_control_path_when_signalled_mid_window(
    tmp_path: Path, signum: signal.Signals
) -> None:
    """A candidate severs the client -> fw control path and the operator's process is then killed
    by the session teardown mid-window: the pre-``try`` snapshot is still restored and connectivity
    comes back with no operator action. Before #450 the process died with the candidate live."""
    candidate = _write_json(tmp_path / "candidate.json", nh.render(_CANDIDATE))
    stopped = _write_json(
        tmp_path / "stopped.json", nh.render(_STOPPED, generator=generate_stopped)
    )
    snapshot = tmp_path / "pre-try-snapshot.json"

    with nh.NetnsSandbox(_TOPO) as sb:
        sb.load(_GOOD)  # the running ruleset safe_apply snapshots and must restore
        with nh.listeners(sb, _TOPO.router, (_CONTROL_PORT,)):
            assert sb.connect(_CLIENT.name, _ROUTER_IP, _CONTROL_PORT) == "open"

            proc = subprocess.Popen(
                _safe_apply_argv(candidate, stopped, snapshot, timeout=_SIGNAL_WINDOW),
                stderr=subprocess.PIPE, text=True,
            )
            try:
                # The candidate is live: the lockout is real and we are inside the guarded window.
                _poll_connect(sb, _CONTROL_PORT, "filtered")
                proc.send_signal(signum)  # the session teardown that used to kill the revert
                _, err = proc.communicate(timeout=60)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

            # Exits non-zero with one clear error: the revert is a completed action, not a success.
            assert proc.returncode == 1, f"expected a clean signalled exit, got {proc.returncode}"
            assert f"error: {signum.name} received: reverting" in err
            assert "Traceback" not in err

            # The proof: connectivity is back, restored from the pre-try snapshot by the signal
            # path alone — the window never elapsed.
            _poll_connect(sb, _CONTROL_PORT, "open")
