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
from .ir import Family, RoutingArtifact, TproxyRoutingArtifact

NFT = "nft"
IP = "ip"

# The ``ip`` family flag per artifact family (ADR-0002): a provider routing table + fwmark rule is
# scoped to one family (v4 or v6, never both), so every ``ip`` invocation carries -4 or -6.
_IP_FAMILY_FLAG = {Family.IPV4: "-4", Family.IPV6: "-6"}

# The default-route prefix per family for a tproxy ``local`` route out ``lo`` (ADR-0051 Part B).
_LOCAL_DEFAULT = {Family.IPV4: "0.0.0.0/0", Family.IPV6: "::/0"}

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


def restore_ruleset(path: Path = DEFAULT_RULESET_PATH) -> None:
    """Load the persisted ruleset from ``path`` live, fail-closed (task #206, ADR-0030).

    The read half of :func:`save_ruleset`: parse the persisted JSON and hand the exact object
    to :func:`apply_ruleset` for one atomic load. A missing file, corrupt JSON, or a payload
    that is not a ruleset is wrapped as :class:`~shorewallnf.errors.ShorewallNFError` *before*
    any nft call, so a failed restore never flushes the live ruleset to an empty (wide-open)
    state. An nft-rejected ruleset raises :class:`~shorewallnf.errors.ConfigError` from
    :func:`apply_ruleset` and commits nothing.
    """
    try:
        text = path.read_text()
    except OSError as err:
        raise ShorewallNFError(f"failed to read persisted ruleset from {path}: {err}") from err
    try:
        ruleset = json.loads(text)
    except json.JSONDecodeError as err:
        raise ShorewallNFError(f"persisted ruleset at {path} is not valid JSON: {err}") from err
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        raise ShorewallNFError(f"persisted ruleset at {path} is not a valid nftables ruleset")
    apply_ruleset(ruleset)


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


# --- provider policy routing via iproute2 (task #235, ADR-0050) ----------------------------
#
# Policy routing lives in the Linux routing subsystem, not nftables, so it is applied with the
# ``ip`` binary rather than ``nft``. The argv is derived purely from the ADR-0050 artifact model
# (so it is unit-testable by capturing argv without a live network); all invocation stays here in
# the shell (ADR-0003).


def routing_install_argv(artifacts: tuple[RoutingArtifact, ...]) -> list[list[str]]:
    """The ``ip`` argv that installs the provider routing artifacts (ADR-0050), per family.

    Per artifact, in order: add the default route via the provider's gateway/interface into its
    routing table, then the fwmark→table selection rule (populate the table before selecting it).
    """
    argv: list[list[str]] = []
    for art in artifacts:
        flag, table = _IP_FAMILY_FLAG[art.family], str(art.table_id)
        argv.append(
            [IP, flag, "route", "add", "default", "via", art.gateway,
             "dev", art.interface, "table", table]
        )
        argv.append([IP, flag, "rule", "add", "fwmark", str(art.fwmark), "table", table])
    return argv


def routing_teardown_argv(artifacts: tuple[RoutingArtifact, ...]) -> list[list[str]]:
    """The ``ip`` argv that removes the provider routing artifacts — idempotent (safe when absent).

    Per artifact, the reverse of install: drop the fwmark selection rule, then flush the table's
    routes. Run before a re-install (so repeated applies don't accumulate) and by stop/clear.
    """
    argv: list[list[str]] = []
    for art in artifacts:
        flag, table = _IP_FAMILY_FLAG[art.family], str(art.table_id)
        argv.append([IP, flag, "rule", "del", "fwmark", str(art.fwmark), "table", table])
        argv.append([IP, flag, "route", "flush", "table", table])
    return argv


def apply_routing(artifacts: tuple[RoutingArtifact, ...]) -> None:
    """Install the provider routing artifacts via iproute2, idempotently and fail-closed (#235).

    **Ordering:** run this *after* the nft ruleset load (:func:`apply_ruleset`) — the fwmark these
    rules select is set in the nftables mangle path (epic #203), and the nft load is the atomic
    core (ADR-0010). First tear down any prior provider artifacts (best-effort — on a clean system
    the removals no-op), then install the current set. An install failure rolls the partial set
    back (a second teardown) and raises :class:`~shorewallnf.errors.ConfigError`, so a failed apply
    never leaves half-configured routing (fail-closed, ADR-0004).
    """
    _run_best_effort(routing_teardown_argv(artifacts))
    for argv in routing_install_argv(artifacts):
        result = subprocess.run(argv, capture_output=True, text=True)
        if result.returncode != 0:
            _run_best_effort(routing_teardown_argv(artifacts))  # roll back to a clean state
            raise ConfigError(
                f"routing artifact rejected by ip ({' '.join(argv)}): {result.stderr.strip()}"
            )


def teardown_routing(artifacts: tuple[RoutingArtifact, ...]) -> None:
    """Remove the provider routing artifacts via iproute2 (idempotent), for stop/clear (#235)."""
    _run_best_effort(routing_teardown_argv(artifacts))


# --- transparent-proxy local-delivery routing via iproute2 (task #294, ADR-0051) -----------
#
# The sibling of the provider routing path above, for the ADR-0051 tproxy artifact: same
# iproute2 lifecycle (install after the nft load, teardown idempotent, fail-closed rollback),
# but a ``local`` route out ``lo`` rather than a default route via a gateway. Both artifact
# channels are applied together after the atomic nft load.


def tproxy_routing_install_argv(artifacts: tuple[TproxyRoutingArtifact, ...]) -> list[list[str]]:
    """The ``ip`` argv that installs the tproxy local-delivery artifacts (ADR-0051), per family.

    Per artifact, in order: add the ``local`` default route out ``lo`` into the reserved table,
    then the fwmark→table selection rule (populate the table before selecting it).
    """
    argv: list[list[str]] = []
    for art in artifacts:
        flag, table = _IP_FAMILY_FLAG[art.family], str(art.table_id)
        argv.append(
            [IP, flag, "route", "add", "local", _LOCAL_DEFAULT[art.family],
             "dev", "lo", "table", table]
        )
        argv.append([IP, flag, "rule", "add", "fwmark", str(art.fwmark), "table", table])
    return argv


def tproxy_routing_teardown_argv(artifacts: tuple[TproxyRoutingArtifact, ...]) -> list[list[str]]:
    """The ``ip`` argv that removes the tproxy artifacts — idempotent (safe when absent).

    Per artifact, the reverse of install: drop the fwmark selection rule, then flush the table's
    routes. Run before a re-install (so repeated applies don't accumulate) and by stop/clear.
    """
    argv: list[list[str]] = []
    for art in artifacts:
        flag, table = _IP_FAMILY_FLAG[art.family], str(art.table_id)
        argv.append([IP, flag, "rule", "del", "fwmark", str(art.fwmark), "table", table])
        argv.append([IP, flag, "route", "flush", "table", table])
    return argv


def apply_tproxy_routing(artifacts: tuple[TproxyRoutingArtifact, ...]) -> None:
    """Install tproxy local-delivery artifacts via iproute2, idempotently and fail-closed (#294).

    **Ordering:** run this *after* the nft ruleset load (:func:`apply_ruleset`) — the fwmark these
    rules select is set in the nftables mangle path (ADR-0051), and the nft load is the atomic core
    (ADR-0010). First tear down any prior tproxy artifacts (best-effort — on a clean system the
    removals no-op), then install the current set. An install failure rolls the partial set back (a
    second teardown) and raises :class:`~shorewallnf.errors.ConfigError`, so a failed apply never
    leaves half-configured routing (fail-closed, ADR-0004).
    """
    _run_best_effort(tproxy_routing_teardown_argv(artifacts))
    for argv in tproxy_routing_install_argv(artifacts):
        result = subprocess.run(argv, capture_output=True, text=True)
        if result.returncode != 0:
            _run_best_effort(tproxy_routing_teardown_argv(artifacts))  # roll back to a clean state
            raise ConfigError(
                f"tproxy routing artifact rejected by ip ({' '.join(argv)}): "
                f"{result.stderr.strip()}"
            )


def teardown_tproxy_routing(artifacts: tuple[TproxyRoutingArtifact, ...]) -> None:
    """Remove tproxy local-delivery artifacts via iproute2 (idempotent), for stop/clear (#294)."""
    _run_best_effort(tproxy_routing_teardown_argv(artifacts))


def _run_best_effort(argvs: list[list[str]]) -> None:
    """Run each ``ip`` argv, ignoring exit status — removals are idempotent (nothing to remove is
    not an error), so their failure must not abort an apply or a teardown."""
    for argv in argvs:
        subprocess.run(argv, capture_output=True, text=True)
