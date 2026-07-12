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
from shorewallnf.ir import (
    TPROXY_MARK,
    TPROXY_TABLE_ID,
    Family,
    OnOffKeep,
    RoutingArtifact,
    Settings,
    TproxyRoutingArtifact,
    YesNoKeep,
)


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


def test_restore_ruleset_converts_listing_form_to_a_scoped_flush_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A snapshot in ``list_ruleset()`` *listing form* must reach nft as a real scoped-flush load.

    Regression for #449: the snapshot safe_apply writes is ``nft --json list ruleset`` output —
    bare ``{"table":…}``/``{"chain":…}``/``{"rule":…}`` objects plus a ``{"metainfo":…}`` header,
    with no ``add`` verb. The old restore handed that straight to ``atomic_load_payload``, whose
    prelude keys off ``add`` → the create-then-delete flush came out empty and the live table was
    never replaced. This drives a realistic listing snapshot through the *real* transform + applier
    (only the nft subprocess seam is stubbed) and asserts the bytes handed to nft carry a genuine
    scoped flush (create+delete of the table) ahead of the wrapped adds — so it would have caught
    the bug without netns.
    """
    listing = {
        "nftables": [
            {"metainfo": {"version": "1.0.9", "release_name": "x", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "filter", "handle": 1}},
            {
                "chain": {
                    "family": "inet", "table": "filter", "name": "input", "handle": 1,
                    "type": "filter", "hook": "input", "prio": 0, "policy": "drop",
                }
            },
            {
                "rule": {
                    "family": "inet", "table": "filter", "chain": "input", "handle": 4,
                    "expr": [{"accept": None}],
                }
            },
        ]
    }
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(listing))

    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    applier.restore_ruleset(path)

    commands = json.loads(seen["input"])["nftables"]
    table = {"family": "inet", "name": "filter"}  # scoped by name — handle stripped, not settable
    # A real, non-empty scoped-flush prelude: create-then-delete of the candidate table (the fix).
    assert commands[0] == {"add": {"table": table}}
    assert commands[1] == {"delete": {"table": table}}
    # The listing objects reach nft in command form: wrapped in ``add``, metainfo dropped, no
    # kernel-assigned handles (which nft rejects on add).
    assert {"add": {"table": table}} in commands[2:]
    assert not any("metainfo" in c for c in commands)
    assert "handle" not in json.dumps(commands)
    # End to end: exactly the atomic-load payload of the normalised command form.
    assert json.loads(seen["input"]) == applier.atomic_load_payload(
        applier._to_command_form(listing)
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


# --- transparent-proxy local-delivery routing artifacts via iproute2 (#294, ADR-0051) --------
#
# The applier lowers ADR-0051 TproxyRoutingArtifacts to `ip route`/`ip rule` argv, per family —
# a `local` route out `lo` rather than a default route via a gateway — and runs them idempotently
# and fail-closed, the sibling lifecycle of provider routing. Hermetic: argv captured, no network.

_TPROXY_ARTS = (
    TproxyRoutingArtifact(table_id=TPROXY_TABLE_ID, fwmark=TPROXY_MARK, family=Family.IPV4),
    TproxyRoutingArtifact(table_id=TPROXY_TABLE_ID, fwmark=TPROXY_MARK, family=Family.IPV6),
)

_T = str(TPROXY_TABLE_ID)  # reserved table id, decimal-rendered (0xFFFFFFFF)
_M = str(TPROXY_MARK)  # reserved fwmark, decimal-rendered (0xFFFFFFFF)


def test_tproxy_routing_install_argv_populates_table_then_selects_it_per_family() -> None:
    assert applier.tproxy_routing_install_argv(_TPROXY_ARTS) == [
        ["ip", "-4", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", _T],
        ["ip", "-4", "rule", "add", "fwmark", _M, "table", _T],
        ["ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", _T],
        ["ip", "-6", "rule", "add", "fwmark", _M, "table", _T],
    ]


def test_tproxy_routing_teardown_argv_drops_rule_then_flushes_table_per_family() -> None:
    assert applier.tproxy_routing_teardown_argv(_TPROXY_ARTS) == [
        ["ip", "-4", "rule", "del", "fwmark", _M, "table", _T],
        ["ip", "-4", "route", "flush", "table", _T],
        ["ip", "-6", "rule", "del", "fwmark", _M, "table", _T],
        ["ip", "-6", "route", "flush", "table", _T],
    ]


def test_apply_tproxy_routing_tears_down_before_installing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_run(monkeypatch)
    applier.apply_tproxy_routing(_TPROXY_ARTS)
    assert calls == (
        applier.tproxy_routing_teardown_argv(_TPROXY_ARTS)
        + applier.tproxy_routing_install_argv(_TPROXY_ARTS)
    )


def test_apply_tproxy_routing_ignores_teardown_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # On a clean system the teardown del/flush return non-zero (nothing to remove); the apply
    # treats teardown as best-effort and still installs, without raising.
    _record_run(monkeypatch, rc_for=lambda cmd: 2 if ("del" in cmd or "flush" in cmd) else 0)
    applier.apply_tproxy_routing(_TPROXY_ARTS)  # must not raise


def test_apply_tproxy_routing_install_failure_raises_and_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_run(monkeypatch, rc_for=lambda cmd: 1 if cmd[2:4] == ["route", "add"] else 0)
    with pytest.raises(ConfigError, match="boom"):
        applier.apply_tproxy_routing(_TPROXY_ARTS)
    # a rollback teardown ran after the failed install, leaving no partial tproxy routing
    teardown = applier.tproxy_routing_teardown_argv(_TPROXY_ARTS)
    assert calls[-len(teardown):] == teardown


def test_teardown_tproxy_routing_runs_the_removal_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_run(monkeypatch, rc_for=lambda cmd: 2)  # nothing to remove; must not raise
    applier.teardown_tproxy_routing(_TPROXY_ARTS)
    assert calls == applier.tproxy_routing_teardown_argv(_TPROXY_ARTS)


def test_apply_tproxy_routing_with_no_tproxy_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_run(monkeypatch)
    applier.apply_tproxy_routing(())
    assert calls == []


# --- kernel sysctl seam: IP_FORWARDING / LOG_MARTIANS / ROUTE_FILTER (#322, ADR-0062) --------
#
# The applier's first kernel mutation outside nftables. The pure `sysctl_plan` maps the tri-state
# Settings toggles to (key, value) writes (only non-Keep contributes); `apply_sysctls` snapshots
# then writes them, restoring the snapshot on any failure (fail-closed rollback). Hermetic: argv
# captured, no root.


def test_sysctl_plan_maps_every_toggle_to_its_keys_in_order() -> None:
    settings = Settings(
        ip_forwarding=OnOffKeep.ON,
        log_martians=YesNoKeep.YES,
        route_filter=YesNoKeep.YES,
    )
    assert applier.sysctl_plan(settings) == [
        ("net.ipv4.ip_forward", "1"),
        ("net.ipv6.conf.all.forwarding", "1"),
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.default.log_martians", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
    ]


def test_sysctl_plan_off_and_no_map_to_zero() -> None:
    settings = Settings(
        ip_forwarding=OnOffKeep.OFF,
        log_martians=YesNoKeep.NO,
        route_filter=YesNoKeep.NO,
    )
    assert all(value == "0" for _key, value in applier.sysctl_plan(settings))


def test_sysctl_plan_keep_and_absent_yield_no_entry() -> None:
    # The all-defaults Settings (absent file) is all-Keep -> touches nothing.
    assert applier.sysctl_plan(Settings()) == []
    # A single non-Keep toggle contributes only its own keys; the Keep ones stay out.
    assert applier.sysctl_plan(Settings(ip_forwarding=OnOffKeep.OFF)) == [
        ("net.ipv4.ip_forward", "0"),
        ("net.ipv6.conf.all.forwarding", "0"),
    ]


def _record_sysctl(
    monkeypatch: pytest.MonkeyPatch, *, snapshot: str = "7", fail_on: str | None = None
) -> list[list[str]]:
    """Stub subprocess.run for sysctl: reads (``-n``) return ``snapshot``; a write of ``fail_on``
    (a ``key=value`` string) returns rc 1. Records every argv."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if cmd[1] == "-w" and cmd[2] == fail_on:
            return subprocess.CompletedProcess(cmd, 1, "", "sysctl: boom")
        return subprocess.CompletedProcess(cmd, 0, snapshot, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_apply_sysctls_snapshots_then_writes_each_planned_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_sysctl(monkeypatch)
    applier.apply_sysctls(Settings(ip_forwarding=OnOffKeep.ON))
    # Every key is read (snapshot) before any write, then written in plan order.
    assert calls == [
        ["sysctl", "-n", "net.ipv4.ip_forward"],
        ["sysctl", "-n", "net.ipv6.conf.all.forwarding"],
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
    ]


def test_apply_sysctls_with_all_keep_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _record_sysctl(monkeypatch)
    applier.apply_sysctls(Settings())  # all-Keep: never reads or writes a sysctl
    assert calls == []


def test_apply_sysctls_restores_snapshot_and_raises_on_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Plan: forwarding(2) + martians(2) + rp_filter(2). Fail the 3rd write (first martians key).
    calls = _record_sysctl(
        monkeypatch, snapshot="7", fail_on="net.ipv4.conf.all.log_martians=1"
    )
    settings = Settings(
        ip_forwarding=OnOffKeep.ON,
        log_martians=YesNoKeep.YES,
        route_filter=YesNoKeep.YES,
    )
    with pytest.raises(ConfigError, match="boom"):
        applier.apply_sysctls(settings)

    writes = [c for c in calls if c[1] == "-w"]
    # The two forwarding keys were written, then the failing martians write; on failure the two
    # already-written keys are restored to their snapshot ("7"), in reverse order. The failing key
    # is never counted as written, so it is not "restored".
    assert writes == [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
        ["sysctl", "-w", "net.ipv4.conf.all.log_martians=1"],  # the rejected write
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=7"],  # rollback (reverse order)
        ["sysctl", "-w", "net.ipv4.ip_forward=7"],
    ]
    # Fail-closed: the rp_filter keys after the failure point are never written.
    assert not any("rp_filter" in c[-1] for c in writes)


# --- read-only live-query seam (task #410, ADR-0065) --------------------------------------


def test_list_ruleset_invokes_nft_json_list_and_parses_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}
    payload = {"nftables": [{"metainfo": {"version": "1.0.9"}}]}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = applier.list_ruleset()

    assert result == payload  # the parsed JSON is returned verbatim
    assert seen["cmd"] == ["nft", "--json", "list", "ruleset"]


def test_list_ruleset_is_read_only_by_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    # The query argv must be a `list` and can never carry a mutating form.
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        # A read-only query streams nothing on stdin — there is no ruleset to load.
        assert kwargs.get("input") is None
        return subprocess.CompletedProcess(cmd, 0, '{"nftables": []}', "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    applier.list_ruleset()

    assert "list" in seen["cmd"]
    for mutating in ("--file", "add", "delete", "flush", "--check", "-f"):
        assert mutating not in seen["cmd"]


def test_list_ruleset_raises_configerror_when_nft_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "nft: command not found")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="command not found"):
        applier.list_ruleset()


# --- read-only conntrack live-query seam (task #412, ADR-0065) -----------------------------


def test_list_connections_invokes_conntrack_list_and_returns_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}
    output = "tcp 6 431999 ESTABLISHED src=192.0.2.2 dst=203.0.113.9 sport=1 dport=443\n"

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, output, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = applier.list_connections()

    assert result == output  # the raw conntrack text is returned verbatim for the pure renderer
    assert seen["cmd"] == ["conntrack", "-L"]


def test_list_connections_is_read_only_by_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    # The query argv must be a `-L` list and can never carry a mutating conntrack form.
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        # A read-only query streams nothing on stdin — there is no state to load.
        assert kwargs.get("input") is None
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    applier.list_connections()

    assert "-L" in seen["cmd"]
    for mutating in ("-D", "-F", "-U", "--delete", "--flush", "--update"):
        assert mutating not in seen["cmd"]


def test_list_connections_missing_binary_raises_shorewallnferror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A missing `conntrack` binary raises FileNotFoundError (an OSError, not a non-zero rc);
    # the seam translates it to one actionable ShorewallNFError (ADR-0004), never a traceback.
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(2, "No such file or directory", "conntrack")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ShorewallNFError, match="conntrack"):
        applier.list_connections()


def test_list_connections_raises_configerror_when_conntrack_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "conntrack v1.4: Operation not supported")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="Operation not supported"):
        applier.list_connections()


# --- read-only journal live-query seam (task #413, ADR-0065) -------------------------------


def test_list_log_reads_kernel_journal_and_returns_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}
    output = "Shorewall:net-fw:DROP:IN=eth0 SRC=203.0.113.7 DST=192.0.2.1 PROTO=TCP\n"

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, output, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = applier.list_log()

    assert result == output  # the raw journal text is returned verbatim for the pure renderer
    assert seen["cmd"] == ["journalctl", "-k", "-o", "cat", "--no-pager"]


def test_list_log_is_read_only_by_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    # The query argv reads kernel messages and streams nothing on stdin — there is no
    # journalctl form here that could mutate the journal or the ruleset.
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        assert kwargs.get("input") is None
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    applier.list_log()

    assert "-k" in seen["cmd"]
    for mutating in ("--rotate", "--vacuum-size", "--vacuum-time", "--flush", "--sync"):
        assert mutating not in seen["cmd"]


def test_list_log_missing_journalctl_raises_shorewallnferror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A missing `journalctl` binary raises FileNotFoundError (an OSError, not a non-zero rc);
    # the seam translates it to one actionable ShorewallNFError (ADR-0004), never a traceback.
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(2, "No such file or directory", "journalctl")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ShorewallNFError, match="journalctl"):
        applier.list_log()


def test_list_log_raises_configerror_when_journalctl_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "Failed to open journal: Permission denied")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="Permission denied"):
        applier.list_log()


# --- short firewall-state predicate + live link-state seam (task #414) ----------------------


def test_firewall_loaded_true_when_owned_table_present() -> None:
    # `nft --json list ruleset` emits bare `{"table": {...}}` objects; any OWNED_TABLES entry
    # means the firewall is loaded.
    ruleset = {
        "nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"table": {"family": "inet", "name": "filter", "handle": 1}},
        ]
    }
    assert applier.firewall_loaded(ruleset) is True


def test_firewall_loaded_false_on_empty_ruleset() -> None:
    # A stopped/cleared firewall leaves no owned table — the short state is not-loaded, not a crash.
    assert applier.firewall_loaded({"nftables": []}) is False
    assert applier.firewall_loaded({}) is False


def test_firewall_loaded_ignores_co_resident_foreign_tables() -> None:
    # A table ShorewallNF does not own must not read as loaded.
    ruleset = {"nftables": [{"table": {"family": "ip", "name": "not-ours", "handle": 9}}]}
    assert applier.firewall_loaded(ruleset) is False


def test_link_states_invokes_ip_json_and_maps_up_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}
    output = json.dumps(
        [
            {"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"]},
            {"ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP"]},
            {"ifname": "eth1", "flags": ["BROADCAST", "MULTICAST"]},
        ]
    )

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, output, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert applier.link_states() == {"lo": True, "eth0": True, "eth1": False}
    assert seen["cmd"] == ["ip", "--json", "link", "show"]


def test_link_states_is_read_only_by_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        assert kwargs.get("input") is None  # a query streams nothing to load
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    applier.link_states()

    assert "show" in seen["cmd"]
    for mutating in ("set", "add", "delete", "del", "flush", "change"):
        assert mutating not in seen["cmd"]


def test_link_states_missing_binary_raises_shorewallnferror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(2, "No such file or directory", "ip")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ShorewallNFError, match="ip"):
        applier.link_states()


def test_link_states_raises_configerror_when_ip_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "ip: something went wrong")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ConfigError, match="something went wrong"):
        applier.link_states()
