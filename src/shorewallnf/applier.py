"""Applier — the imperative shell that validates/loads a ruleset with nftables.

All ``nft`` invocation lives here (ADR-0003 imperative shell). :func:`check_ruleset` dry-run
validates the generated JSON ruleset by shelling out to the system ``nft`` binary in check mode
(``nft --check --json --file -``, the equivalent of ``nft -c``), raising
:class:`~shorewallnf.errors.ConfigError` if nft rejects it.

The generator emits the ruleset JSON with the stdlib ``json`` module, so generation needs no
nftables tooling. ``nft --check`` reads the kernel ruleset cache, so it needs CAP_NET_ADMIN
(root); test tiers that lack it gate on availability — see ``tests/golden_harness.py``.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from .errors import ConfigError

NFT = "nft"


def atomic_load_payload(ruleset: dict[str, Any]) -> dict[str, Any]:
    """Wrap ``ruleset`` so a load replaces only its own tables in one transaction (ADR-0010).

    For each ``add table`` in the generated ruleset, prepend an idempotent create-then-delete
    (``add table`` then ``delete table``) so the table is emptied whether or not it pre-existed,
    then append the full ruleset that re-adds the tables, chains and rules. The scope is derived
    from the input tables — never ``flush ruleset``, which would clobber co-resident tables.
    """
    prelude: list[dict[str, Any]] = []
    for command in ruleset["nftables"]:
        table = command.get("add", {}).get("table")
        if table is not None:
            prelude.append({"add": {"table": dict(table)}})
            prelude.append({"delete": {"table": dict(table)}})
    return {"nftables": [*prelude, *ruleset["nftables"]]}


def check_ruleset(ruleset: dict[str, Any]) -> None:
    """Dry-run validate the nftables JSON ``ruleset`` (like ``nft -c``); raise on rejection."""
    result = subprocess.run(
        [NFT, "--check", "--json", "--file", "-"],
        input=json.dumps(ruleset),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigError(f"generated ruleset rejected by nft: {result.stderr.strip()}")
