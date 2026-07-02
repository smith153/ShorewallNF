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
