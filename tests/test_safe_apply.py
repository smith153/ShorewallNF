"""Tests for the safe-apply primitive (task #437, ADR-0067).

The primitive wires the shipped snapshot/apply/revert building blocks in ``applier`` into one
``snapshot -> apply -> (timeout-)revert`` helper behind the ``try DIR [timeout]`` verb. These tests
are hermetic: they stub the module-level nft seams (``list_ruleset``/``apply_ruleset``/…) and inject
a no-op ``wait``, so they assert the revert *policy* without a live kernel and without sleeping. The
full netns lockout-recovery behavioural proof is deferred to #440.
"""

from __future__ import annotations

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
