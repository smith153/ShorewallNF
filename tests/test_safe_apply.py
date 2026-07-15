"""Tests for the safe-apply primitive (task #437, ADR-0067).

The primitive wires the shipped snapshot/apply/revert building blocks in ``applier`` into one
``snapshot -> apply -> (timeout-)revert`` helper behind the ``try DIR [timeout]`` verb. These tests
are hermetic: they stub the module-level nft seams (``list_ruleset``/``apply_ruleset``/…) and inject
a no-op ``wait``, so they assert the revert *policy* without a live kernel and without sleeping. The
full netns lockout-recovery behavioural proof is deferred to #440.
"""

from __future__ import annotations

import io
import os
import signal
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from shorewallnf import applier
from shorewallnf.errors import ConfigError, ShorewallNFError

CANDIDATE: dict[str, Any] = {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}
STOPPED: dict[str, Any] = {"nftables": [{"add": {"table": {"family": "inet", "name": "s"}}}]}
RUNNING: dict[str, Any] = {"nftables": [{"table": {"family": "inet", "name": "filter"}}]}


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    running: dict[str, Any],
    was_running: bool,
    restore_raises: bool = False,
) -> tuple[list[str], list[tuple[dict[str, Any], Path]], list[dict[str, Any]]]:
    """Stub the applier's nft seams; return ``(seq, saved, applied)`` recorders.

    ``seq`` is the ordered op log, ``saved`` the ``(ruleset, path)`` snapshot writes, ``applied``
    every ruleset handed to :func:`applier.apply_ruleset`.
    """
    seq: list[str] = []
    saved: list[tuple[dict[str, Any], Path]] = []
    applied: list[dict[str, Any]] = []

    def _save(rs: dict[str, Any], path: Path) -> None:
        seq.append("save")
        saved.append((rs, path))

    def _apply(rs: dict[str, Any]) -> None:
        seq.append("apply")
        applied.append(rs)

    def _restore(path: Path) -> None:
        seq.append("restore")
        if restore_raises:
            raise ShorewallNFError("snapshot unreadable")

    monkeypatch.setattr(applier, "list_ruleset", lambda: running)
    monkeypatch.setattr(applier, "firewall_loaded", lambda r: was_running)
    monkeypatch.setattr(applier, "save_ruleset", _save)
    monkeypatch.setattr(applier, "check_ruleset", lambda rs: seq.append("check"))
    monkeypatch.setattr(applier, "apply_ruleset", _apply)
    monkeypatch.setattr(applier, "restore_ruleset", _restore)
    monkeypatch.setattr(applier, "clear_ruleset", lambda: seq.append("clear"))
    return seq, saved, applied


def test_no_timeout_applies_candidate_without_snapshot_or_revert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    waited: list[int] = []
    applier.safe_apply(CANDIDATE, STOPPED, timeout=None, wait=waited.append)
    assert seq == ["check", "apply"]  # compile->check->apply, no revert armed
    assert saved == []  # without a timeout there is nothing to revert to
    assert applied == [CANDIDATE]
    assert waited == []  # the wait seam is never entered without a timeout


def test_timeout_snapshots_running_to_own_path_then_reverts_to_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seq, saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    waited: list[int] = []
    snap = tmp_path / "pre-try.json"
    applier.safe_apply(CANDIDATE, STOPPED, timeout=30, snapshot_path=snap, wait=waited.append)
    assert seq == ["save", "check", "apply", "restore"]  # snapshot before apply, revert after wait
    assert saved == [(RUNNING, snap)]  # the *running* ruleset, to its own path
    assert snap != applier.DEFAULT_RULESET_PATH  # never the persisted ruleset
    assert applied == [CANDIDATE]
    assert waited == [30]  # the injected wait covered the whole window


def test_timeout_reverts_to_clear_when_nothing_was_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, saved, applied = _wire(monkeypatch, running={"nftables": []}, was_running=False)
    applier.safe_apply(CANDIDATE, STOPPED, timeout=5, wait=lambda _s: None)
    assert saved == []  # nothing running -> no snapshot to persist
    assert seq == ["check", "apply", "clear"]  # revert target is clear, not a stale snapshot
    assert applied == [CANDIDATE]


def test_restore_failure_falls_through_to_stopped_safe_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, saved, applied = _wire(
        monkeypatch, running=RUNNING, was_running=True, restore_raises=True
    )
    applier.safe_apply(CANDIDATE, STOPPED, timeout=5, wait=lambda _s: None)
    # restore raised -> fail-closed: load the stopped safe state (ADR-0021), never wide open.
    assert seq == ["save", "check", "apply", "restore", "apply"]
    assert applied == [CANDIDATE, STOPPED]


def test_candidate_apply_failure_propagates_and_arms_no_revert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)

    def _boom(rs: dict[str, Any]) -> None:
        seq.append("apply")
        raise ConfigError("ruleset rejected by nft: boom")

    monkeypatch.setattr(applier, "apply_ruleset", _boom)
    with pytest.raises(ConfigError, match="boom"):
        applier.safe_apply(CANDIDATE, STOPPED, timeout=5, wait=lambda _s: None)
    # atomic load fails closed -> running unchanged; no revert (restore/clear) is reached.
    assert "restore" not in seq
    assert "clear" not in seq


# --- confirm hook: the safe-reload/safe-start interactive-confirm seam (task #439, ADR-0067) ---


def test_no_timeout_keep_returns_true(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, running=RUNNING, was_running=True)
    # kept as the final running state -> the caller may persist.
    assert applier.safe_apply(CANDIDATE, STOPPED, timeout=None) is True


def test_timeout_revert_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, running=RUNNING, was_running=True)
    kept = applier.safe_apply(CANDIDATE, STOPPED, timeout=5, wait=lambda _s: None)
    assert kept is False  # unconditional revert (try) -> not kept


def test_confirm_true_keeps_candidate_and_never_waits_or_reverts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seq, saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    waited: list[int] = []
    seen: list[int] = []

    def _confirm_yes(window: int) -> bool:
        seen.append(window)
        return True

    snap = tmp_path / "pre.json"
    kept = applier.safe_apply(
        CANDIDATE, STOPPED, timeout=30, snapshot_path=snap,
        wait=waited.append, confirm=_confirm_yes,
    )
    assert kept is True  # operator confirmed -> keep the candidate, caller persists
    assert seq == ["save", "check", "apply"]  # snapshot taken, but no revert
    assert applied == [CANDIDATE]
    assert seen == [30]  # confirm was handed the window
    assert waited == []  # the confirm seam replaces the blind wait


def test_confirm_false_reverts_to_snapshot_and_returns_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seq, saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    snap = tmp_path / "pre.json"
    kept = applier.safe_apply(
        CANDIDATE, STOPPED, timeout=30, snapshot_path=snap, confirm=lambda _t: False
    )
    assert kept is False  # negative confirm -> revert
    assert seq == ["save", "check", "apply", "restore"]  # revert to the captured snapshot
    assert saved == [(RUNNING, snap)]
    assert snap != applier.DEFAULT_RULESET_PATH  # persisted ruleset never touched on revert


def test_confirm_false_clears_when_nothing_was_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, saved, _applied = _wire(monkeypatch, running={"nftables": []}, was_running=False)
    kept = applier.safe_apply(CANDIDATE, STOPPED, timeout=5, confirm=lambda _t: False)
    assert kept is False
    assert saved == []  # nothing running -> no snapshot
    assert seq == ["check", "apply", "clear"]  # revert target is clear, not a stale snapshot


def test_confirm_false_restore_failure_falls_through_to_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, _saved, applied = _wire(
        monkeypatch, running=RUNNING, was_running=True, restore_raises=True
    )
    kept = applier.safe_apply(CANDIDATE, STOPPED, timeout=5, confirm=lambda _t: False)
    assert kept is False
    assert seq == ["save", "check", "apply", "restore", "apply"]  # fail-closed to stopped
    assert applied == [CANDIDATE, STOPPED]


def test_confirm_not_reached_when_candidate_apply_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seq, _saved, _applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    confirmed: list[int] = []

    def _boom(rs: dict[str, Any]) -> None:
        seq.append("apply")
        raise ConfigError("ruleset rejected by nft: boom")

    def _confirm(timeout: int) -> bool:
        confirmed.append(timeout)
        return True

    monkeypatch.setattr(applier, "apply_ruleset", _boom)
    with pytest.raises(ConfigError, match="boom"):
        applier.safe_apply(CANDIDATE, STOPPED, timeout=5, confirm=_confirm)
    assert confirmed == []  # apply fails fast before the operator is ever prompted


# --- prompt_confirm: the default terminal-prompt implementation of the confirm seam (#439) -----


def _fake_stdin(monkeypatch: pytest.MonkeyPatch, *, ready: bool, line: str) -> None:
    """Wire the ``select``/``stdin`` seams so ``prompt_confirm`` runs without a real TTY."""

    class _Stdin:
        def isatty(self) -> bool:
            return True  # the usable-stdin precondition (#450); the unusable cases are below

        def readline(self) -> str:
            return line

    def _select(
        rlist: Any, wlist: Any, xlist: Any, timeout: float
    ) -> tuple[list[Any], list[Any], list[Any]]:
        return (list(rlist), [], []) if ready else ([], [], [])

    monkeypatch.setattr("sys.stdin", _Stdin())
    monkeypatch.setattr("select.select", _select)


@pytest.mark.parametrize("answer", ["y", "yes", "Y", "YES", "  yes \n"])
def test_prompt_confirm_true_on_affirmative(
    monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    _fake_stdin(monkeypatch, ready=True, line=answer)
    assert applier.prompt_confirm(60) is True


@pytest.mark.parametrize("answer", ["n\n", "no\n", "\n", "maybe\n"])
def test_prompt_confirm_false_on_negative_or_blank(
    monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    _fake_stdin(monkeypatch, ready=True, line=answer)
    assert applier.prompt_confirm(60) is False


def test_prompt_confirm_false_on_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_stdin(monkeypatch, ready=True, line="")  # readline "" == EOF
    assert applier.prompt_confirm(60) is False


def test_prompt_confirm_false_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_stdin(monkeypatch, ready=False, line="y\n")  # window elapsed, nothing readable
    assert applier.prompt_confirm(60) is False


# --- #450: the revert must survive a signalled death and an unusable confirm seam -------------
#
# The defect: the revert was plain foreground control flow *after* the wait/confirm seam, so any
# death of the process once the candidate was live (sshd SIGHUPing the session a bad rule just
# severed) or any exception out of the seam left the candidate loaded permanently. The fix traps
# SIGHUP/SIGINT/SIGTERM into a raise and reverts from a `finally` entered before the apply.
# SIGKILL is deliberately out of the threat model: being signalled is ours to handle, vanishing is
# infrastructure's (a vanished process reverts on the next boot's `shorewallnf restore`).

_TRAPPED = [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]


def _self_signal(signum: signal.Signals) -> Callable[[int], None]:
    """A ``wait`` seam standing in for a signalled death mid-window."""

    def _wait(_seconds: int) -> None:
        os.kill(os.getpid(), signum)

    return _wait


@pytest.mark.parametrize("signum", _TRAPPED, ids=lambda s: s.name)
def test_signal_during_wait_reverts_to_snapshot_and_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, signum: signal.Signals
) -> None:
    """A signalled death mid-window still reverts: the trap raises and the `finally` restores the
    pre-apply snapshot, rather than the process dying with the candidate live (#450 mode 1)."""
    seq, saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    snap = tmp_path / "pre-try.json"

    with pytest.raises(ShorewallNFError, match=signum.name):
        applier.safe_apply(
            CANDIDATE, STOPPED, timeout=30, snapshot_path=snap, wait=_self_signal(signum)
        )

    assert seq == ["save", "check", "apply", "restore"]  # the revert ran on the way out
    assert saved == [(RUNNING, snap)]
    assert applied == [CANDIDATE]


@pytest.mark.parametrize("signum", _TRAPPED, ids=lambda s: s.name)
def test_signal_during_confirm_reverts_to_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, signum: signal.Signals
) -> None:
    """One mechanism covers both seams: the interactive confirm window reverts on a signal too."""
    seq, _saved, _applied = _wire(monkeypatch, running=RUNNING, was_running=True)

    def _confirm(_timeout: int) -> bool:
        os.kill(os.getpid(), signum)
        raise AssertionError("the trap must interrupt the confirm seam")

    with pytest.raises(ShorewallNFError, match=signum.name):
        applier.safe_apply(
            CANDIDATE, STOPPED, timeout=30, snapshot_path=tmp_path / "p.json", confirm=_confirm
        )
    assert seq == ["save", "check", "apply", "restore"]


def test_signal_reverts_to_clear_when_nothing_was_running(monkeypatch: pytest.MonkeyPatch) -> None:
    seq, _saved, _applied = _wire(monkeypatch, running={"nftables": []}, was_running=False)
    with pytest.raises(ShorewallNFError, match="SIGHUP"):
        applier.safe_apply(CANDIDATE, STOPPED, timeout=5, wait=_self_signal(signal.SIGHUP))
    assert seq == ["check", "apply", "clear"]  # revert target is clear, not a stale snapshot


def test_signal_path_restore_failure_falls_through_to_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC6: fail-closed is preserved when the revert is reached from the signal path."""
    seq, _saved, applied = _wire(
        monkeypatch, running=RUNNING, was_running=True, restore_raises=True
    )
    with pytest.raises(ShorewallNFError, match="SIGHUP"):
        applier.safe_apply(CANDIDATE, STOPPED, timeout=5, wait=_self_signal(signal.SIGHUP))
    assert seq == ["save", "check", "apply", "restore", "apply"]
    assert applied == [CANDIDATE, STOPPED]  # stopped safe state (ADR-0021), never wide open


def test_handlers_are_installed_before_the_candidate_is_applied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """AC3: the guarded region is entered *before* apply_ruleset, so a signal arriving from the
    moment the candidate is live always reverts."""
    seq, _saved, _applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    armed: list[bool] = []

    def _apply(rs: dict[str, Any]) -> None:
        seq.append("apply")
        armed.append(all(callable(signal.getsignal(s)) for s in _TRAPPED))

    monkeypatch.setattr(applier, "apply_ruleset", _apply)
    applier.safe_apply(
        CANDIDATE, STOPPED, timeout=5, snapshot_path=tmp_path / "p.json", wait=lambda _s: None
    )
    assert armed == [True]  # handlers were already ours while the candidate went live


def test_handlers_are_restored_after_the_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The trap is scoped to the window: safe_apply leaves the caller's dispositions as it found
    them, on both the revert and the keep path."""
    _wire(monkeypatch, running=RUNNING, was_running=True)
    before = [signal.getsignal(s) for s in _TRAPPED]

    applier.safe_apply(
        CANDIDATE, STOPPED, timeout=5, snapshot_path=tmp_path / "p.json", wait=lambda _s: None
    )
    assert [signal.getsignal(s) for s in _TRAPPED] == before

    applier.safe_apply(
        CANDIDATE, STOPPED, timeout=5, snapshot_path=tmp_path / "p.json", confirm=lambda _t: True
    )
    assert [signal.getsignal(s) for s in _TRAPPED] == before


def test_no_timeout_installs_no_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC5: the no-timeout path is unchanged — nothing to revert, so nothing is trapped."""
    seq, _saved, _applied = _wire(monkeypatch, running=RUNNING, was_running=True)
    before = [signal.getsignal(s) for s in _TRAPPED]
    seen: list[list[Any]] = []

    def _apply(rs: dict[str, Any]) -> None:
        seq.append("apply")
        seen.append([signal.getsignal(s) for s in _TRAPPED])

    monkeypatch.setattr(applier, "apply_ruleset", _apply)
    assert applier.safe_apply(CANDIDATE, STOPPED, timeout=None) is True
    assert seen == [before]  # dispositions untouched while applying


@pytest.mark.parametrize(
    "err", [io.UnsupportedOperation("fileno"), ValueError("I/O operation on closed file")]
)
def test_confirm_seam_exception_still_reverts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, err: Exception
) -> None:
    """#450 mode 2: a non-ShorewallNFError out of the confirm seam left the candidate live. The
    guarded region reverts on *any* exception on the way out."""
    seq, _saved, applied = _wire(monkeypatch, running=RUNNING, was_running=True)

    def _boom(_timeout: int) -> bool:
        raise err

    with pytest.raises(type(err)):
        applier.safe_apply(
            CANDIDATE, STOPPED, timeout=5, snapshot_path=tmp_path / "p.json", confirm=_boom
        )
    assert seq == ["save", "check", "apply", "restore"]  # pre-apply state restored
    assert applied == [CANDIDATE]


# --- #450: prompt_confirm fails closed on a stdin it cannot confirm on -------------------------


def test_prompt_confirm_rejects_stdin_without_a_fileno(monkeypatch: pytest.MonkeyPatch) -> None:
    """`select` raised `io.UnsupportedOperation: fileno` here — not a ShorewallNFError, so the CLI
    let it out as a traceback with the candidate live. Now one clear error."""
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    with pytest.raises(ShorewallNFError, match="not a TTY"):
        applier.prompt_confirm(60)


def test_prompt_confirm_rejects_closed_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`select` raised `ValueError: I/O operation on closed file` here — same defect."""
    handle = (tmp_path / "stdin").open("w+")
    handle.close()
    monkeypatch.setattr("sys.stdin", handle)
    with pytest.raises(ShorewallNFError, match="not a TTY"):
        applier.prompt_confirm(60)


def test_prompt_confirm_rejects_a_detached_dev_null_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC7: `nohup`-style stdin is readable immediately, so the old seam read EOF, returned False
    and reverted with a zero-length window — silently no-opping safe-reload. Fail clearly instead.
    """
    with open(os.devnull) as devnull:
        monkeypatch.setattr("sys.stdin", devnull)
        with pytest.raises(ShorewallNFError, match="not a TTY"):
            applier.prompt_confirm(60)


def test_signal_during_the_load_reverts_though_a_rejection_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The two failures out of ``apply_ruleset`` are not the same. nft rejecting the candidate is
    proof it never ran (atomic load) — reverting would be pointless, and a failing restore would
    knock a healthy firewall into the stopped state, so the #437 fail-fast contract holds. Being
    *signalled* mid-load leaves the outcome unknown, so it must revert."""
    seq, _saved, _applied = _wire(monkeypatch, running=RUNNING, was_running=True)

    def _signalled_apply(rs: dict[str, Any]) -> None:
        seq.append("apply")
        os.kill(os.getpid(), signal.SIGHUP)  # the load may or may not have committed

    monkeypatch.setattr(applier, "apply_ruleset", _signalled_apply)
    with pytest.raises(ShorewallNFError, match="SIGHUP"):
        applier.safe_apply(
            CANDIDATE, STOPPED, timeout=5, snapshot_path=tmp_path / "p.json", wait=lambda _s: None
        )
    assert seq == ["save", "check", "apply", "restore"]  # unknown state -> revert, fail-closed
