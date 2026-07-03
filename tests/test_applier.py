"""Tests for the applier's ``nft --check`` dry-run (task #165).

The applier validates a generated ruleset by shelling out to the ``nft`` binary in check mode.
These tests are hermetic: they stub ``subprocess.run`` so they exercise the invocation and the
error mapping without needing ``nft`` (or the CAP_NET_ADMIN it requires) installed.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

import tests.golden_harness as gh
from shorewallnf import applier
from shorewallnf.errors import ConfigError, ShorewallNFError
from shorewallnf.ir import Family, RoutingArtifact


def test_check_ruleset_invokes_nft_check_json_with_ruleset_on_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ruleset = {"nftables": [{"add": {"table": {"family": "inet", "name": "t"}}}]}
    applier.check_ruleset(ruleset)

    assert seen["cmd"] == ["nft", "--check", "--json", "--file", "-"]
    assert json.loads(seen["input"]) == ruleset  # the generated JSON is fed on stdin


def test_check_ruleset_raises_configerror_when_nft_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "nft: boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="boom"):
        applier.check_ruleset({"nftables": []})


# --- atomic scoped-replace prelude (ADR-0010) ---------------------------------------------


def test_atomic_load_payload_prepends_create_then_delete_per_table() -> None:
    ruleset = {
        "nftables": [
            {"add": {"table": {"family": "inet", "name": "filter"}}},
            {"add": {"chain": {"family": "inet", "table": "filter", "name": "input"}}},
            {"add": {"table": {"family": "inet", "name": "nat"}}},
            {"add": {"chain": {"family": "inet", "table": "nat", "name": "prerouting"}}},
        ]
    }
    payload = applier.atomic_load_payload(ruleset)
    prelude = [
        {"add": {"table": {"family": "inet", "name": "filter"}}},
        {"delete": {"table": {"family": "inet", "name": "filter"}}},
        {"add": {"table": {"family": "inet", "name": "nat"}}},
        {"delete": {"table": {"family": "inet", "name": "nat"}}},
    ]
    # The prelude (create-then-delete per table, in ruleset order) precedes the full ruleset.
    assert payload["nftables"] == [*prelude, *ruleset["nftables"]]


def test_atomic_load_payload_derives_tables_from_input() -> None:
    # Only one table in the input -> prelude covers only that table, not a hardcoded pair.
    ruleset = {
        "nftables": [
            {"add": {"table": {"family": "inet", "name": "filter"}}},
            {"add": {"chain": {"family": "inet", "table": "filter", "name": "input"}}},
        ]
    }
    payload = applier.atomic_load_payload(ruleset)
    assert payload["nftables"][:2] == [
        {"add": {"table": {"family": "inet", "name": "filter"}}},
        {"delete": {"table": {"family": "inet", "name": "filter"}}},
    ]
    tables_in_prelude = [
        c["delete"]["table"]["name"]
        for c in payload["nftables"]
        if "delete" in c and "table" in c["delete"]
    ]
    assert tables_in_prelude == ["filter"]


def test_atomic_load_payload_has_no_flush_ruleset() -> None:
    ruleset = {
        "nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]
    }
    payload = applier.atomic_load_payload(ruleset)
    assert not any("flush" in c for c in payload["nftables"])


def test_atomic_load_payload_does_not_mutate_input() -> None:
    ruleset = {
        "nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]
    }
    original = json.loads(json.dumps(ruleset))
    applier.atomic_load_payload(ruleset)
    assert ruleset == original


# --- clear_payload / clear_ruleset: wide-open scoped clear (task #208) ---------------------


def test_clear_payload_deletes_fixed_owned_table_set() -> None:
    # Wide-open, config-independent: delete-only prelude for the fixed owned set
    # (inet filter + inet nat), add-then-delete each, and nothing else.
    payload = applier.clear_payload()
    assert payload["nftables"] == [
        {"add": {"table": {"family": "inet", "name": "filter"}}},
        {"delete": {"table": {"family": "inet", "name": "filter"}}},
        {"add": {"table": {"family": "inet", "name": "nat"}}},
        {"delete": {"table": {"family": "inet", "name": "nat"}}},
    ]


def test_clear_payload_has_no_re_add_and_no_flush() -> None:
    payload = applier.clear_payload()
    # Delete-only: exactly two add and two delete commands, no ruleset re-add.
    assert sum("add" in c for c in payload["nftables"]) == 2
    assert sum("delete" in c for c in payload["nftables"]) == 2
    assert not any("flush" in c for c in payload["nftables"])


def test_clear_payload_never_names_a_co_resident_table() -> None:
    payload = applier.clear_payload()
    names = [
        next(iter(c.values()))["table"]["name"]
        for c in payload["nftables"]
    ]
    assert "myvpn" not in names
    assert set(names) == {"filter", "nat"}


def test_clear_ruleset_loads_clear_payload_with_dry_run_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    applier.clear_ruleset()

    assert seen["cmd"] == ["nft", "--json", "--file", "-"]
    assert json.loads(seen["input"]) == applier.clear_payload()


def test_clear_ruleset_raises_configerror_when_nft_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "nft: boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="boom"):
        applier.clear_ruleset()


# --- apply_ruleset: fail-closed live load (task #179) --------------------------------------


def test_apply_ruleset_loads_atomic_payload_with_dry_run_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ruleset = {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}
    applier.apply_ruleset(ruleset)  # exit-0 path returns None cleanly

    # Real load (dry-run OFF): no ``--check`` flag, unlike check_ruleset.
    assert seen["cmd"] == ["nft", "--json", "--file", "-"]
    assert "--check" not in seen["cmd"]
    # The payload fed to nft is the scoped atomic-replace payload, not the raw ruleset.
    assert json.loads(seen["input"]) == applier.atomic_load_payload(ruleset)


def test_apply_ruleset_raises_configerror_when_nft_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "nft: boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="boom"):
        applier.apply_ruleset({"nftables": []})


@pytest.mark.skipif(
    not gh.nft_available(),
    reason="apply_ruleset live load needs a usable nft (CAP_NET_ADMIN)",
)
def test_apply_ruleset_loads_valid_ruleset_live() -> None:
    # Scoped atomic replace of a uniquely-named probe table — leaves co-resident tables alone.
    ruleset = {
        "nftables": [{"add": {"table": {"family": "inet", "name": "snf_apply_probe"}}}]
    }
    try:
        applier.apply_ruleset(ruleset)  # rc 0, no raise
    finally:
        subprocess.run(
            ["nft", "delete", "table", "inet", "snf_apply_probe"],
            capture_output=True,
            text=True,
        )


# --- save_ruleset: persist the effective ruleset to disk (task #205) -----------------------


def test_save_ruleset_round_trips_the_exact_applied_object(tmp_path: Path) -> None:
    ruleset = {
        "nftables": [
            {"add": {"table": {"family": "inet", "name": "filter"}}},
            {"add": {"chain": {"family": "inet", "table": "filter", "name": "input"}}},
        ]
    }
    path = tmp_path / "state" / "ruleset.json"
    applier.save_ruleset(ruleset, path)
    with path.open() as fh:
        assert json.load(fh) == ruleset  # exactly the applied object, round-tripped


def test_save_ruleset_writes_owner_only_permissions(tmp_path: Path) -> None:
    path = tmp_path / "ruleset.json"
    applier.save_ruleset({"nftables": []}, path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600  # owner read/write only, no group/other access


def test_save_ruleset_is_atomic_leaves_no_temp_on_success(tmp_path: Path) -> None:
    path = tmp_path / "ruleset.json"
    applier.save_ruleset({"nftables": []}, path)
    # only the final file remains — no leftover temp files in the directory.
    assert [p.name for p in tmp_path.iterdir()] == ["ruleset.json"]


def test_save_ruleset_atomic_never_truncates_existing_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ruleset.json"
    good = {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}
    applier.save_ruleset(good, path)

    # A write that fails mid-serialisation must not corrupt the pre-existing good file.
    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(ShorewallNFError):
        applier.save_ruleset({"nftables": []}, path)
    with path.open() as fh:
        assert json.load(fh) == good  # original intact, no partial/truncated content


def test_save_ruleset_raises_shorewallnferror_on_write_failure(tmp_path: Path) -> None:
    # Parent path component is a file, so the directory cannot be created — a clear failure.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    with pytest.raises(ShorewallNFError):
        applier.save_ruleset({"nftables": []}, blocker / "ruleset.json")


def test_default_ruleset_path_is_stable_and_documented() -> None:
    assert applier.DEFAULT_RULESET_PATH == Path("/var/lib/shorewallnf/ruleset.json")


# --- restore_ruleset: load the persisted ruleset from disk (task #206) ----------------------


def test_restore_ruleset_loads_persisted_file_via_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ruleset = {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}
    path = tmp_path / "ruleset.json"
    path.write_text(json.dumps(ruleset))

    applied: list[Any] = []
    monkeypatch.setattr(applier, "apply_ruleset", lambda r: applied.append(r))
    applier.restore_ruleset(path)
    # The exact persisted object is handed to the atomic applier (round-trip of save).
    assert applied == [ruleset]


def test_restore_ruleset_missing_file_raises_and_never_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    applied = False

    def record(_r: Any) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(applier, "apply_ruleset", record)
    with pytest.raises(ShorewallNFError):
        applier.restore_ruleset(tmp_path / "does-not-exist.json")
    assert applied is False  # aborts before any load — never flushes to an empty ruleset


def test_restore_ruleset_corrupt_json_raises_before_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ruleset.json"
    path.write_text("{not valid json")

    applied = False

    def record(_r: Any) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(applier, "apply_ruleset", record)
    with pytest.raises(ShorewallNFError):
        applier.restore_ruleset(path)
    assert applied is False


def test_restore_ruleset_non_ruleset_json_raises_before_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Valid JSON, but not a ruleset payload — must be rejected before touching nft.
    path = tmp_path / "ruleset.json"
    path.write_text('["not", "a", "ruleset"]')

    applied = False

    def record(_r: Any) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(applier, "apply_ruleset", record)
    with pytest.raises(ShorewallNFError):
        applier.restore_ruleset(path)
    assert applied is False


def test_restore_ruleset_propagates_nft_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ruleset.json"
    path.write_text(json.dumps({"nftables": []}))

    def rejecting_apply(_r: Any) -> None:
        raise ConfigError("ruleset rejected by nft: boom")

    monkeypatch.setattr(applier, "apply_ruleset", rejecting_apply)
    with pytest.raises(ConfigError, match="boom"):
        applier.restore_ruleset(path)


@pytest.mark.skipif(
    not gh.nft_available(),
    reason="restore_ruleset live round-trip needs a usable nft (CAP_NET_ADMIN)",
)
def test_restore_ruleset_round_trips_a_saved_ruleset_live(tmp_path: Path) -> None:
    # save then restore re-applies the same scoped, uniquely-named probe table.
    ruleset = {
        "nftables": [{"add": {"table": {"family": "inet", "name": "snf_restore_probe"}}}]
    }
    path = tmp_path / "ruleset.json"
    applier.save_ruleset(ruleset, path)
    try:
        applier.restore_ruleset(path)  # rc 0, no raise
    finally:
        subprocess.run(
            ["nft", "delete", "table", "inet", "snf_restore_probe"],
            capture_output=True,
            text=True,
        )


# --- provider routing artifacts via iproute2 (#235, ADR-0050) ----------------
#
# The applier lowers ADR-0050 RoutingArtifacts to `ip route`/`ip rule` argv, per family, and
# runs them idempotently and fail-closed. These tests capture the argv without a live network.

_ARTS = (
    RoutingArtifact(table_id=1, fwmark=1, gateway="192.0.2.1", interface="eth0",
                    family=Family.IPV4),
    RoutingArtifact(table_id=3, fwmark=3, gateway="2001:db8::1", interface="eth2",
                    family=Family.IPV6),
)


def _record_run(monkeypatch: pytest.MonkeyPatch, rc_for: Any = None) -> list[list[str]]:
    """Stub subprocess.run to record argv; rc_for(cmd) -> returncode (default 0)."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        rc = rc_for(cmd) if rc_for is not None else 0
        return subprocess.CompletedProcess(cmd, rc, "", "ip: boom" if rc else "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_routing_install_argv_populates_table_then_selects_it_per_family() -> None:
    assert applier.routing_install_argv(_ARTS) == [
        ["ip", "-4", "route", "add", "default", "via", "192.0.2.1", "dev", "eth0", "table", "1"],
        ["ip", "-4", "rule", "add", "fwmark", "1", "table", "1"],
        ["ip", "-6", "route", "add", "default", "via", "2001:db8::1", "dev", "eth2", "table", "3"],
        ["ip", "-6", "rule", "add", "fwmark", "3", "table", "3"],
    ]


def test_routing_teardown_argv_drops_rule_then_flushes_table_per_family() -> None:
    assert applier.routing_teardown_argv(_ARTS) == [
        ["ip", "-4", "rule", "del", "fwmark", "1", "table", "1"],
        ["ip", "-4", "route", "flush", "table", "1"],
        ["ip", "-6", "rule", "del", "fwmark", "3", "table", "3"],
        ["ip", "-6", "route", "flush", "table", "3"],
    ]


def test_apply_routing_tears_down_before_installing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_run(monkeypatch)
    applier.apply_routing(_ARTS)
    assert calls == applier.routing_teardown_argv(_ARTS) + applier.routing_install_argv(_ARTS)


def test_apply_routing_ignores_teardown_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    # On a clean system the teardown del/flush return non-zero (nothing to remove); apply_routing
    # treats teardown as best-effort and still installs, without raising.
    _record_run(monkeypatch, rc_for=lambda cmd: 2 if ("del" in cmd or "flush" in cmd) else 0)
    applier.apply_routing(_ARTS)  # must not raise


def test_apply_routing_install_failure_raises_and_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_run(monkeypatch, rc_for=lambda cmd: 1 if cmd[2:4] == ["route", "add"] else 0)
    with pytest.raises(ConfigError, match="boom"):
        applier.apply_routing(_ARTS)
    # a rollback teardown ran after the failed install, leaving no partial provider routing
    teardown = applier.routing_teardown_argv(_ARTS)
    assert calls[-len(teardown):] == teardown


def test_teardown_routing_runs_the_removal_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_run(monkeypatch, rc_for=lambda cmd: 2)  # nothing to remove; must not raise
    applier.teardown_routing(_ARTS)
    assert calls == applier.routing_teardown_argv(_ARTS)


def test_apply_routing_with_no_providers_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_run(monkeypatch)
    applier.apply_routing(())
    assert calls == []
