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
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .errors import ConfigError, ShorewallNFError
from .ir import (
    Family,
    OnOffKeep,
    RoutingArtifact,
    Settings,
    TproxyRoutingArtifact,
    YesNoKeep,
)

NFT = "nft"
IP = "ip"
SYSCTL = "sysctl"
CONNTRACK = "conntrack"
JOURNALCTL = "journalctl"

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

# Safe-apply timeout: a positive integer with an optional lowercase s/m/h unit (default seconds).
_TIMEOUT_RE = re.compile(r"^(\d+)([smh]?)$")
_TIMEOUT_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600}


def parse_timeout(value: str) -> int:
    """Parse a safe-apply timeout argument into whole seconds (task #436).

    Accepts a bare positive integer (seconds) or the ``Ns``/``Nm``/``Nh`` suffix forms, e.g.
    ``45s`` → ``45``, ``5m`` → ``300``, ``2h`` → ``7200``. Anything else — empty, zero, negative,
    non-numeric, fractional, or an unknown/uppercase suffix — fails fast with a single
    :class:`~shorewallnf.errors.ShorewallNFError` (ADR-0004).
    """
    match = _TIMEOUT_RE.match(value)
    if match is None:
        raise ShorewallNFError(
            f"invalid timeout {value!r}: expected a positive number of seconds, "
            "optionally suffixed with s, m, or h (e.g. 30, 45s, 5m, 2h)"
        )
    number = int(match.group(1))
    if number <= 0:
        raise ShorewallNFError(f"invalid timeout {value!r}: must be a positive duration")
    return number * _TIMEOUT_UNIT_SECONDS[match.group(2)]


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


def list_ruleset() -> dict[str, Any]:
    """Read-only live query: return the parsed ``nft --json list ruleset`` output (task #410).

    The read-only twin of :func:`apply_ruleset`, beside it in the shell (ADR-0003): it shells
    ``nft --json list ruleset`` and parses the live ruleset to JSON for the renderer. Read-only is
    structural — ``nft list`` has no mutating form and nothing is streamed on stdin, so the query
    can never alter the ruleset (ADR-0065). ``list ruleset`` succeeds on a stopped/cleared firewall
    (an empty ruleset), so graceful degradation needs no special-casing here — the renderer emits an
    empty-but-valid section. A non-zero rc (e.g. ``nft`` missing) raises
    :class:`~shorewallnf.errors.ConfigError`, caught once in the CLI shell (ADR-0004).
    """
    result = subprocess.run(
        [NFT, "--json", "list", "ruleset"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigError(f"nft list failed: {result.stderr.strip()}")
    parsed: dict[str, Any] = json.loads(result.stdout)
    return parsed


def firewall_loaded(ruleset: dict[str, Any]) -> bool:
    """True when a ShorewallNF-owned table is present in the live ruleset (task #414).

    A pure predicate over :func:`list_ruleset` output — whose objects are the bare ``{"table":
    {...}}`` listing form, not the ``{"add": …}`` command form. The firewall reads as loaded when
    any :data:`OWNED_TABLES` entry appears; a stopped or cleared firewall leaves none, so this
    returns ``False`` without special-casing. Co-resident foreign tables are ignored. This is the
    short-state seam the read-only ``status`` verb reports from (ADR-0065).
    """
    owned = {(t["family"], t["name"]) for t in OWNED_TABLES}
    return any(
        (table := command.get("table")) is not None
        and (table.get("family"), table.get("name")) in owned
        for command in ruleset.get("nftables", [])
    )


def link_states() -> dict[str, bool]:
    """Read-only live query: map each network link to its up/down state (task #414).

    Shells ``ip --json link show`` and folds the result to ``{ifname: is_up}``, where up means the
    ``UP`` admin flag is set (the ``ip link set … up`` sense). The injectable ``ip`` seam for the
    ``status -i`` per-interface report (ADR-0003 shell): structurally read-only — ``link show`` is
    a query with no mutating form and nothing streamed on stdin. A missing ``ip`` binary raises
    :class:`~shorewallnf.errors.ShorewallNFError`; a non-zero rc raises
    :class:`~shorewallnf.errors.ConfigError`, both caught once in the CLI shell (ADR-0004).
    """
    try:
        result = subprocess.run(
            [IP, "--json", "link", "show"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as err:
        raise ShorewallNFError(
            "ip utility not found; install iproute2 to report interface state"
        ) from err
    if result.returncode != 0:
        raise ConfigError(f"ip link failed: {result.stderr.strip()}")
    links: list[dict[str, Any]] = json.loads(result.stdout)
    return {link["ifname"]: "UP" in link.get("flags", []) for link in links}


def list_connections() -> str:
    """Read-only live query: return raw ``conntrack -L`` output (task #412, ADR-0065).

    The conntrack sibling of :func:`list_ruleset`, beside it in the shell (ADR-0003): it shells
    the ``conntrack`` list form only and hands the raw text to the pure renderer. Read-only is
    structural — ``-L`` is a list, never a mutating form (``-D``/``-F``/``-U``), and nothing is
    streamed on stdin. A missing ``conntrack`` binary makes ``subprocess.run`` raise
    ``FileNotFoundError`` (an ``OSError``, not a non-zero rc), which is translated to one
    actionable :class:`~shorewallnf.errors.ShorewallNFError` (fail-fast, ADR-0004) rather than a
    traceback. ``conntrack -L`` exits 0 tracking nothing (including a stopped firewall), so the
    zero-connection case degrades to an empty-but-valid render, not an error. Any other non-zero
    rc raises :class:`~shorewallnf.errors.ConfigError`, caught once in the CLI shell.
    """
    try:
        result = subprocess.run(
            [CONNTRACK, "-L"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as err:
        raise ShorewallNFError(
            "conntrack utility not found; install conntrack-tools to show connections"
        ) from err
    if result.returncode != 0:
        raise ConfigError(f"conntrack list failed: {result.stderr.strip()}")
    return result.stdout


def list_log() -> str:
    """Read-only live query: return raw systemd kernel-journal text (task #413, ADR-0065).

    The journal sibling of :func:`list_connections`, beside it in the shell (ADR-0003): nft ``log``
    statements land in the kernel journal (ShorewallNF packages only systemd, ADR-0064; there is no
    ``LOGFILE`` setting, ADR-0061), so it shells ``journalctl -k`` (kernel messages, ``-o cat`` for
    the bare message text) and hands the raw output to the pure renderer, which filters it to
    firewall lines and bounds the tail. Read-only is structural — ``-k`` reads kernel messages, no
    mutating journal form (``--rotate``/``--vacuum-*``/``--flush``) is used, and nothing is streamed
    on stdin. A missing ``journalctl`` binary makes ``subprocess.run`` raise ``FileNotFoundError``
    (an ``OSError``, not a non-zero rc), translated to one actionable
    :class:`~shorewallnf.errors.ShorewallNFError` (fail-fast, ADR-0004) rather than a traceback. An
    empty journal exits 0, so the no-messages case degrades to an empty-but-valid render, not an
    error. Any other non-zero rc raises :class:`~shorewallnf.errors.ConfigError`, caught once in the
    CLI shell.
    """
    try:
        result = subprocess.run(
            [JOURNALCTL, "-k", "-o", "cat", "--no-pager"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as err:
        raise ShorewallNFError(
            "journalctl not found; systemd journal is required to show the firewall log"
        ) from err
    if result.returncode != 0:
        raise ConfigError(f"journalctl read failed: {result.stderr.strip()}")
    return result.stdout


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


# --- safe-apply: snapshot -> apply -> (timeout-)revert primitive (task #437, ADR-0067) -----

#: Pre-``try`` snapshot path. Kept off :data:`DEFAULT_RULESET_PATH` so a ``try`` never mutates the
#: persisted ruleset (ADR-0030/ADR-0067) — the running state is captured here, not to the saved one.
SAFE_APPLY_SNAPSHOT_PATH = Path("/var/lib/shorewallnf/pre-try-snapshot.json")


def safe_apply(
    candidate: dict[str, Any],
    stopped: dict[str, Any],
    *,
    timeout: int | None = None,
    snapshot_path: Path = SAFE_APPLY_SNAPSHOT_PATH,
    wait: Callable[[int], None] = time.sleep,
) -> None:
    """Apply ``candidate`` with auto-revert — the safe-apply primitive (task #437, ADR-0067).

    One reusable helper wiring the shipped building blocks: capture the *running* ruleset
    (:func:`list_ruleset`), dry-run check then atomically load ``candidate``
    (:func:`check_ruleset`/:func:`apply_ruleset`), and — when ``timeout`` is given — wait the
    window, then revert to the pre-``try`` state. A check/apply failure raises (fail-fast,
    ADR-0004) before any revert is armed; the load is atomic, so a rejected ``candidate`` leaves the
    running ruleset unchanged.

    The revert target is the pre-``try`` state: the captured snapshot when a firewall was running
    (:func:`firewall_loaded` true), or :func:`clear_ruleset` when nothing was. The snapshot is
    written to its **own** ``snapshot_path`` — never :data:`DEFAULT_RULESET_PATH` — so a ``try``
    does not touch the persisted ruleset. If the restore itself fails, the primitive falls closed to
    the ``stopped`` safe-state ruleset (ADR-0021), never a wide-open firewall. ``wait`` is
    injectable so the timeout window is unit-testable without sleeping.
    """
    running = list_ruleset()
    was_running = firewall_loaded(running)
    if timeout is not None and was_running:
        save_ruleset(running, snapshot_path)
    check_ruleset(candidate)
    apply_ruleset(candidate)
    if timeout is None:
        return
    wait(timeout)
    if not was_running:
        clear_ruleset()
        return
    try:
        restore_ruleset(snapshot_path)
    except ShorewallNFError:
        apply_ruleset(stopped)  # fail-closed: stopped safe state, never wide open (ADR-0021/0004)


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


# --- kernel sysctls: IP_FORWARDING / LOG_MARTIANS / ROUTE_FILTER (task #322, ADR-0062) ------
#
# The applier's first kernel mutation outside nftables. The ``shorewallnf.conf`` tri-state toggles
# (ADR-0061) lower to ``sysctl`` writes here in the shell (ADR-0003); the pure :func:`sysctl_plan`
# maps a :class:`Settings` to the exact (key, value) writes, so it is unit-tested without root.
# Sysctls are applied *after* the atomic nft load (ADR-0010) — like the routing artifacts above —
# so ``IP_FORWARDING=On`` only enables forwarding once the firewall that governs forwarded traffic
# is in place; :func:`apply_sysctls` snapshots first and restores on any failure (fail-closed).

# The sysctl keys each toggle drives. Family-aware (ADR-0002): forwarding spans IPv4 + IPv6; martian
# logging and reverse-path filtering are IPv4 ``conf`` keys (no IPv6 kernel equivalent). ``all`` +
# ``default`` cover existing and future interfaces.
_FORWARDING_KEYS = ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
_LOG_MARTIANS_KEYS = ("net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians")
_ROUTE_FILTER_KEYS = ("net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter")


def sysctl_plan(settings: Settings) -> list[tuple[str, str]]:
    """The ``(key, value)`` sysctl writes ``settings`` requests, in deterministic order (ADR-0062).

    Only non-``Keep`` toggles contribute; a ``Keep`` (or absent, i.e. all-defaults) setting yields
    no entry, so the kernel value is left untouched. ``On``/``Yes`` → ``"1"``, ``Off``/``No`` →
    ``"0"``. Pure: no I/O, so it is unit-tested without root.
    """
    plan: list[tuple[str, str]] = []
    if settings.ip_forwarding is not OnOffKeep.KEEP:
        value = "1" if settings.ip_forwarding is OnOffKeep.ON else "0"
        plan += [(key, value) for key in _FORWARDING_KEYS]
    if settings.log_martians is not YesNoKeep.KEEP:
        value = "1" if settings.log_martians is YesNoKeep.YES else "0"
        plan += [(key, value) for key in _LOG_MARTIANS_KEYS]
    if settings.route_filter is not YesNoKeep.KEEP:
        value = "1" if settings.route_filter is YesNoKeep.YES else "0"
        plan += [(key, value) for key in _ROUTE_FILTER_KEYS]
    return plan


def _sysctl_write_argv(key: str, value: str) -> list[str]:
    return [SYSCTL, "-w", f"{key}={value}"]


def _sysctl_read_argv(key: str) -> list[str]:
    return [SYSCTL, "-n", key]


def _sysctl_read(key: str) -> str | None:
    """The current value of ``key``, or ``None`` when the key is absent (nothing to restore)."""
    result = subprocess.run(_sysctl_read_argv(key), capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def apply_sysctls(settings: Settings) -> None:
    """Mutate the kernel sysctls ``settings`` requests, fail-closed with rollback (#322, ADR-0062).

    **Ordering:** run this *after* the atomic nft load (:func:`apply_ruleset`) so
    ``IP_FORWARDING=On`` enables forwarding only once the firewall governing forwarded traffic is
    loaded (mirroring the routing artifacts above, ADR-0010). Snapshot every
    target key's current value, then write the :func:`sysctl_plan` values in order. On the first
    write failure, restore every already-written key to its snapshot (reverse order) and raise
    :class:`~shorewallnf.errors.ConfigError`, so a partial failure never leaves the toggles half-set
    (fail-closed, ADR-0004/0021). ``Keep`` toggles contribute nothing and are never read or written.
    """
    plan = sysctl_plan(settings)
    if not plan:
        return
    snapshot = {key: _sysctl_read(key) for key, _value in plan}
    written: list[str] = []
    for key, value in plan:
        result = subprocess.run(_sysctl_write_argv(key, value), capture_output=True, text=True)
        if result.returncode != 0:
            _restore_sysctls(snapshot, written)
            raise ConfigError(f"sysctl {key}={value} rejected: {result.stderr.strip()}")
        written.append(key)


def _restore_sysctls(snapshot: dict[str, str | None], written: list[str]) -> None:
    """Restore each already-written key to its snapshot value (reverse of the write order).

    A key whose snapshot is ``None`` (it was absent) is skipped — there is nothing to restore.
    Restores are best-effort: rollback must not itself raise over an already-failing apply.
    """
    for key in reversed(written):
        prior = snapshot[key]
        if prior is not None:
            subprocess.run(_sysctl_write_argv(key, prior), capture_output=True, text=True)
