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
