"""Applier — the imperative shell that validates/loads a ruleset with nftables.

All ``nft`` invocation lives here (ADR-0003 imperative shell). :func:`check_ruleset` dry-run
validates the generated JSON ruleset by shelling out to the system ``nft`` binary in check mode
(``nft --check --json --file -``, the equivalent of ``nft -c``), raising
:class:`~shorewallnf.errors.ConfigError` if nft rejects it. :func:`apply_ruleset` is its
dry-run-OFF twin: it loads the ruleset live in one atomic transaction, fail-closed.

The generator emits the ruleset JSON with the stdlib ``json`` module, so generation needs no
nftables tooling. ``nft --check`` reads the kernel ruleset cache, so it needs CAP_NET_ADMIN
(root); test tiers that lack it gate on availability — see ``tests/golden_harness.py``.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .errors import ConfigError, ShorewallNFError

NFT = "nft"

# The fixed set of ShorewallNF-owned tables. ``clear`` deletes this constant set regardless of
# what any config compiles to — a NAT-less config must still clear a stale ``nat`` table.
OWNED_TABLES: tuple[dict[str, str], ...] = (
    {"family": "inet", "name": "filter"},
    {"family": "inet", "name": "nat"},
)


def clear_payload() -> dict[str, Any]:
    """Build the wide-open scoped-clear transaction (task #208, ADR-0010 idiom).

    Delete-only: for each ShorewallNF-owned table emit an idempotent create-then-delete
    (``add table`` then ``delete table``) and nothing else — no rule re-add, no ``flush``.
    The scope is the fixed :data:`OWNED_TABLES` constant, not a compiled config, so a stale
    table is cleared even when the current config would not create it. Co-resident tables are
    never named, so they are untouched.
    """
    commands: list[dict[str, Any]] = []
    for table in OWNED_TABLES:
        commands.append({"add": {"table": dict(table)}})
        commands.append({"delete": {"table": dict(table)}})
    return {"nftables": commands}


def clear_ruleset() -> None:
    """Load the scoped-clear payload live, fail-closed (task #208, ADR-0010/0004).

    Hands nft the one atomic :func:`clear_payload` transaction (``nft --json --file -``). A
    non-zero rc raises :class:`~shorewallnf.errors.ConfigError`, leaving the live ruleset
    unchanged.
    """
    result = subprocess.run(
        [NFT, "--json", "--file", "-"],
        input=json.dumps(clear_payload()),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigError(f"ruleset rejected by nft: {result.stderr.strip()}")


#: Stable on-disk location of the effective ruleset — the save-on-apply target (ADR-0030).
DEFAULT_RULESET_PATH = Path("/var/lib/shorewallnf/ruleset.json")


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


def apply_ruleset(ruleset: dict[str, Any]) -> None:
    """Load ``ruleset`` live, fail-closed (task #179, ADR-0010/0004).

    The dry-run-OFF twin of :func:`check_ruleset`: it scopes the load with
    :func:`atomic_load_payload` and hands nft the one JSON transaction (``nft --json --file -``,
    no ``--check``). nftables applies the command list atomically, so a rejected ruleset commits
    nothing and the live ruleset is left unchanged; a non-zero rc raises
    :class:`~shorewallnf.errors.ConfigError` carrying nft's error text.
    """
    result = subprocess.run(
        [NFT, "--json", "--file", "-"],
        input=json.dumps(atomic_load_payload(ruleset)),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigError(f"ruleset rejected by nft: {result.stderr.strip()}")


def save_ruleset(ruleset: dict[str, Any], path: Path = DEFAULT_RULESET_PATH) -> None:
    """Persist the exact applied ``ruleset`` JSON to ``path``, atomically (task #205, ADR-0030).

    Writes the same object handed to :func:`apply_ruleset` (no atomic-load wrapping) so it
    round-trips via ``json.load``. The file is created owner-only (``0o600``) and published with
    a temp-write-then-``os.replace`` so a reader never sees a partial or truncated file and an
    interrupted write leaves any prior copy intact. Any I/O failure surfaces as
    :class:`~shorewallnf.errors.ShorewallNFError` rather than passing silently (ADR-0004).
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(ruleset, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    except OSError as err:
        raise ShorewallNFError(f"failed to save ruleset to {path}: {err}") from err
