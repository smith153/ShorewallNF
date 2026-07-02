"""Tests for the applier's ``nft --check`` dry-run (task #165).

The applier validates a generated ruleset by shelling out to the ``nft`` binary in check mode.
These tests are hermetic: they stub ``subprocess.run`` so they exercise the invocation and the
error mapping without needing ``nft`` (or the CAP_NET_ADMIN it requires) installed.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from shorewallnf import applier
from shorewallnf.errors import ConfigError


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
