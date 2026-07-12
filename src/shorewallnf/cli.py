"""Command-line entry point — the imperative shell.

Parses arguments, dispatches a verb, and is the single place a ``ShorewallNFError`` is
caught (ADR-0004): the pure core raises; the shell prints one clean message to stderr
and returns a non-zero exit code. See docs/adr/0004-error-handling.md and
docs/module-layout.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from . import reader
from .applier import (
    DEFAULT_RULESET_PATH,
    apply_ruleset,
    apply_sysctls,
    check_ruleset,
    clear_ruleset,
    firewall_loaded,
    link_states,
    list_connections,
    list_log,
    list_ruleset,
    parse_timeout,
    prompt_confirm,
    restore_ruleset,
    safe_apply,
    save_ruleset,
)
from .errors import ShorewallNFError
from .generator import generate, generate_stopped
from .ir import Settings
from .parser import parse_config, parse_settings
from .preprocessor import SourceLine, parse_params, preprocess_file
from .renderer import (
    render_connections,
    render_log,
    render_policies,
    render_rules,
    render_status,
    render_zones,
)
from .resolver import resolve
from .validator import validate

_VERB_HELP = {
    "check": "preprocess and validate the config; emit no ruleset",
    "compile": "compile the config into an nftables ruleset",
    "apply": "compile, dry-run check, load the ruleset, then save it to disk",
    "start": "bring the firewall up: compile, dry-run check, then atomically load the ruleset",
    "reload": "compile, dry-run check, then atomically replace the running ruleset",
    "restart": "alias of reload: atomically replace the running ruleset",
    "stop": "drop to the stopped safe state: still admits declared admin access, drops the rest",
    "clear": "remove all ShorewallNF tables, leaving traffic unfiltered",
    "restore": "reload the last persisted ruleset from disk, fail-closed",
}

# Verbs that operate on persisted/live state, not a config directory, take no positional.
_NO_CONFIG_VERBS = frozenset({"restore"})

# Read-only visibility verbs (ADR-0065). `show`/`list`/`ls` are exact synonyms dispatching
# identically; each is a *nested* verb group (verb -> object -> options) taking no config_dir.
_SHOW_VERBS = ("show", "list", "ls")
_SHOW_TABLES = ("filter", "nat", "mangle", "raw")

# start/reload/restart share apply's compile->check->apply mechanism (incremental diff
# deferred, #175); they differ only in the confirmation line the operator sees.
_LIFECYCLE_MESSAGE = {"start": "started", "reload": "reloaded", "restart": "reloaded"}

# safe-reload/safe-start share the interactive safe-apply mechanism (task #439); like
# start/reload they differ only in the confirmation line the operator sees.
_SAFE_MESSAGE = {"safe-reload": "safe-reloaded", "safe-start": "safe-started"}


def preprocess(config_dir: str | Path) -> dict[str, list[SourceLine]]:
    """Read a config directory and run the pure preprocessor over each known file.

    Reads ``params`` (if present) for the variable map, then composes the preprocessor
    pipeline (conditionals, ``?FORMAT``/``?SECTION``, substitution) over every other known
    config file present. Returns ``{filename: preprocessed lines}`` (``params`` is consumed,
    not emitted). This is the shell seam (ADR-0003): I/O via the Reader lives here, the
    transforms stay pure in ``preprocessor``.
    """
    present = reader.discover(config_dir)
    params = parse_params(reader.read_file(config_dir, "params")) if "params" in present else {}
    # ``params`` is consumed for substitution; ``shorewallnf.conf`` is non-tabular and never
    # substituted (ADR-0061) — both are excluded from the tabular preprocessing stream.
    skip = {"params", reader.SETTINGS_FILE}
    return {
        name: preprocess_file(reader.read_file(config_dir, name), name, params)
        for name in present
        if name not in skip
    }


def _read_settings(config_dir: str | Path) -> Settings:
    """Read ``shorewallnf.conf`` into a frozen :class:`Settings` (ADR-0061), or all-defaults.

    Its absence is normal and silent — an absent file yields ``Settings()`` and changes no
    output; a malformed one fails fast in :func:`~shorewallnf.parser.parse_settings`.
    """
    if reader.SETTINGS_FILE not in reader.discover(config_dir):
        return Settings()
    text = reader.read_file(config_dir, reader.SETTINGS_FILE)
    return parse_settings(text, path=reader.SETTINGS_FILE)


def compile_config(config_dir: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Compile a config directory into the base ``inet`` nftables ruleset (JSON).

    The shell seam composing the whole pipeline: preprocess (I/O) → parse into the IR →
    resolve macros/actions → validate → generate. Returns the ``python3-nftables`` JSON the
    compile verb emits and the applier can dry-run load.
    """
    ruleset = parse_config(preprocess(config_dir), _read_settings(config_dir))
    return generate(validate(resolve(ruleset)))


def compile_stopped(config_dir: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Compile a config directory into the stopped safe-state ruleset (ADR-0021, JSON).

    The same pre-generation pipeline as :func:`compile_config`, but the generator emits the
    fail-safe stopped state: only the declared admin-access ``stoppedrules`` plus the no-lockout
    baseline (loopback + established/related), default-drop otherwise. With zero admin rules the
    baseline alone still admits the operator, so ``stop`` never silently locks anyone out.
    """
    ruleset = parse_config(preprocess(config_dir), _read_settings(config_dir))
    return generate_stopped(validate(resolve(ruleset)))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shorewallnf",
        description="Compile a Shorewall-style config directory into nftables rules.",
    )
    sub = parser.add_subparsers(dest="verb", required=True)
    for verb, help_text in _VERB_HELP.items():
        verb_parser = sub.add_parser(verb, help=help_text)
        if verb not in _NO_CONFIG_VERBS:
            verb_parser.add_argument(
                "config_dir", help="path to the Shorewall-style config directory"
            )
    for verb in _SHOW_VERBS:
        _add_show_group(sub, verb)
    _add_status_verb(sub)
    _add_dump_verb(sub)
    _add_try_verb(sub)
    for verb in _SAFE_MESSAGE:
        _add_safe_verb(sub, verb)
    return parser


def _add_safe_verb(sub: argparse._SubParsersAction[Any], verb: str) -> None:
    """Add an interactive safe-apply verb — ``safe-reload``/``safe-start`` (task #439, ADR-0067).

    Like ``try``, these need an *optional* ``-t/--timeout`` flag rather than a flat config verb, so
    each gets its own parser. Both are privileged: compile → dry-run check → atomically load the
    candidate, then prompt the operator to confirm within the window; on confirm the candidate is
    kept **and persisted**, on a negative answer or the window elapsing it auto-reverts to the
    pre-apply state (see :func:`~shorewallnf.applier.safe_apply`).
    """
    safe_parser = sub.add_parser(
        verb,
        help="apply a config, then keep+persist it only if the operator confirms; else auto-revert",
    )
    safe_parser.add_argument("config_dir", help="path to the Shorewall-style config directory")
    safe_parser.add_argument(
        "-t",
        "--timeout",
        metavar="timeout",
        help="confirmation window before auto-revert (e.g. 30, 45s, 5m, 2h; default 60s)",
    )


def _add_try_verb(sub: argparse._SubParsersAction[Any]) -> None:
    """Add the safe-apply ``try DIR [timeout]`` verb (task #437, ADR-0067).

    Unlike the flat config verbs, ``try`` takes an *optional* ``timeout`` positional in addition to
    the required ``config_dir``, so it has its own parser. It is privileged (mutates the live
    ruleset) and non-persisting; with a timeout it auto-reverts to the pre-``try`` state after the
    window elapses (see :func:`~shorewallnf.applier.safe_apply`).
    """
    try_parser = sub.add_parser(
        "try",
        help="apply a config with auto-revert; an optional timeout reverts to the pre-try state",
    )
    try_parser.add_argument("config_dir", help="path to the Shorewall-style config directory")
    try_parser.add_argument(
        "timeout",
        nargs="?",
        help="auto-revert after this window if given (e.g. 30, 45s, 5m, 2h)",
    )


def _add_status_verb(sub: argparse._SubParsersAction[Any]) -> None:
    """Add the read-only ``status`` verb (task #414, ADR-0065).

    The short form reads the live ruleset (no config dir); ``-i <config_dir>`` additionally reports
    per-declared-interface up/down state, so it takes the config directory as its value.
    """
    status_parser = sub.add_parser(
        "status", help="report short firewall state (read-only); -i adds per-interface state"
    )
    status_parser.add_argument(
        "-i",
        "--interfaces",
        dest="status_config_dir",
        metavar="config_dir",
        help="also report per-declared-interface up/down state (from the config dir)",
    )


def _add_dump_verb(sub: argparse._SubParsersAction[Any]) -> None:
    """Add the read-only ``dump`` verb (task #415, ADR-0065).

    A consolidated diagnostic report — live ruleset + declared zones/policies + tracked
    connections + a bounded log tail — so it takes the config directory (for the IR sections
    and ``LOGFORMAT``), mirroring ``show log``/``status -i``.
    """
    dump_parser = sub.add_parser(
        "dump",
        help="emit a consolidated read-only diagnostic report "
        "(ruleset + zones/policies + connections + log)",
    )
    dump_parser.add_argument("config_dir", help="path to the Shorewall-style config directory")


def _add_show_group(sub: argparse._SubParsersAction[Any], verb: str) -> None:
    """Add a read-only visibility verb group (``show``/``list``/``ls``, ADR-0065).

    A *nested* subparser (verb -> object -> options), unlike the flat config verbs. Objects differ
    in their source: ``rules`` reads the live ruleset and ``connections`` reads live conntrack
    state (both take no ``config_dir``), while ``zones`` and ``policies`` are compile-time
    declarations not recoverable from live kernel state — they render the config IR, taking a
    ``config_dir`` positional. ``log`` reads live kernel-journal state but takes an *optional*
    ``config_dir`` (only to read ``LOGFORMAT``) plus ``-n``/``--lines``. ``_dispatch`` routes by
    ``show_object``; the remaining siblings (#414-#415) add more objects under this same group.
    """
    show_parser = sub.add_parser(verb, help="display firewall state (read-only)")
    objects = show_parser.add_subparsers(dest="show_object", required=True)
    rules = objects.add_parser("rules", help="show the live packet-filter rules")
    rules.add_argument(
        "-t", "--table", choices=_SHOW_TABLES, default="filter", help="table to show"
    )
    rules.add_argument("chains", nargs="*", help="chains to show (default: all in the table)")
    objects.add_parser(
        "connections", help="show currently kernel-tracked connections (live, read-only)"
    )
    zones = objects.add_parser("zones", help="show declared zones and their members (from config)")
    zones.add_argument("config_dir", help="path to the Shorewall-style config directory")
    policies = objects.add_parser(
        "policies", help="show the inter-zone default-policy matrix (from config)"
    )
    policies.add_argument("config_dir", help="path to the Shorewall-style config directory")
    log = objects.add_parser("log", help="show a bounded tail of recent firewall log messages")
    log.add_argument(
        "config_dir",
        nargs="?",
        help="config directory to read LOGFORMAT from (optional; default template otherwise)",
    )
    log.add_argument(
        "-n",
        "--lines",
        type=int,
        default=20,
        help="most-recent matching lines to show (default 20)",
    )


def _dispatch_show(args: argparse.Namespace) -> int:
    """Route a read-only ``show``/``list``/``ls`` object (ADR-0065); ``list``/``ls`` are synonyms.

    ``rules`` renders the live ruleset, ``connections`` the live conntrack table, and ``log`` a
    bounded tail of firewall lines from the systemd kernel journal (all live, read-only);
    ``zones``/``policies`` render the compiled config IR reached through the pipeline seam
    (compile-time declarations, not recoverable from live kernel state).
    """
    if args.show_object == "rules":
        chains = tuple(args.chains) or None
        print(render_rules(list_ruleset(), table=args.table, chains=chains))
        return 0
    if args.show_object == "connections":
        print(render_connections(list_connections()))
        return 0
    if args.show_object == "log":
        # config_dir is optional: read LOGFORMAT from it when given, else the default template.
        logformat = (
            _read_settings(args.config_dir).logformat if args.config_dir else Settings().logformat
        )
        print(render_log(list_log(), logformat=logformat, lines=args.lines))
        return 0
    ruleset = parse_config(preprocess(args.config_dir), _read_settings(args.config_dir))
    if args.show_object == "zones":
        print(render_zones(ruleset.zones))
        return 0
    # policies
    print(render_policies(ruleset.policies))
    return 0


#: Bound on the log tail dump shows, matching the `show log` default (#413).
_DUMP_LOG_LINES = 20


def _dump_section(label: str, produce: Callable[[], str]) -> str:
    """Render one dump section, or an actionable in-section note if its source is unavailable.

    Graceful degradation (#415): a per-section collection failure (``nft``/``conntrack``/journal
    missing, firewall stopped, …) surfaces as a ``ShorewallNFError`` from the seam; it is caught
    and rendered under ``label`` so one failing section never aborts the whole report.
    """
    try:
        return produce()
    except ShorewallNFError as err:
        return f"{label}\n\n  (unavailable: {err})\n"


def _dump_ir_sections(config_dir: str | Path) -> list[str]:
    """The zones and policies sections, both derived from the one compiled-IR seam (#411).

    They share a source, so they degrade together: if the config can't be read/parsed, each is
    still emitted as its own labelled section carrying the same actionable note.
    """
    try:
        ir = parse_config(preprocess(config_dir), _read_settings(config_dir))
    except ShorewallNFError as err:
        note = f"  (unavailable: {err})\n"
        return [f"Zones\n\n{note}", f"Policies\n\n{note}"]
    return [render_zones(ir.zones), render_policies(ir.policies)]


def _render_dump(config_dir: str | Path) -> str:
    """Compose the consolidated read-only diagnostic report (#415, ADR-0065).

    A pure aggregator over the already-merged read-only seams — live ruleset, declared
    zones/policies (compiled IR), tracked connections, and a bounded log tail — concatenated in
    order behind labelled section headers. It invents no new collection or renderer and mutates
    nothing; every section degrades independently (see :func:`_dump_section`).
    """
    try:
        logformat = _read_settings(config_dir).logformat
    except ShorewallNFError:
        logformat = Settings().logformat  # config unreadable: still show the tail, default filter
    sections = [
        _dump_section("Ruleset", lambda: render_rules(list_ruleset(), table="filter")),
        *_dump_ir_sections(config_dir),
        _dump_section("Connections", lambda: render_connections(list_connections())),
        _dump_section(
            "Firewall log",
            lambda: render_log(list_log(), logformat=logformat, lines=_DUMP_LOG_LINES),
        ),
    ]
    return "\n".join(sections)


def _dispatch(args: argparse.Namespace) -> int:
    if args.verb in _SHOW_VERBS:
        return _dispatch_show(args)
    if args.verb == "status":
        loaded = firewall_loaded(list_ruleset())
        if args.status_config_dir is None:
            print(render_status(loaded))
            return 0
        config_ir = parse_config(
            preprocess(args.status_config_dir), _read_settings(args.status_config_dir)
        )
        print(render_status(loaded, config_ir.interfaces, link_states()))
        return 0
    if args.verb == "dump":
        print(_render_dump(args.config_dir), end="")
        return 0
    if args.verb == "check":
        streams = preprocess(args.config_dir)
        lines = sum(len(s) for s in streams.values())
        print(f"OK: {args.config_dir}: {len(streams)} files, {lines} preprocessed lines")
        return 0
    if args.verb == "apply":
        ruleset = compile_config(args.config_dir)
        check_ruleset(ruleset)
        apply_ruleset(ruleset)
        apply_sysctls(_read_settings(args.config_dir))
        save_ruleset(ruleset)
        print(f"applied: {args.config_dir}")
        return 0
    if args.verb in _LIFECYCLE_MESSAGE:
        ruleset = compile_config(args.config_dir)
        check_ruleset(ruleset)
        apply_ruleset(ruleset)
        apply_sysctls(_read_settings(args.config_dir))
        print(f"{_LIFECYCLE_MESSAGE[args.verb]}: {args.config_dir}")
        return 0
    if args.verb == "stop":
        ruleset = compile_stopped(args.config_dir)
        check_ruleset(ruleset)
        apply_ruleset(ruleset)
        print(f"stopped: {args.config_dir}")
        return 0
    if args.verb == "try":
        timeout = parse_timeout(args.timeout) if args.timeout is not None else None
        candidate = compile_config(args.config_dir)
        stopped = compile_stopped(args.config_dir)
        safe_apply(candidate, stopped, timeout=timeout)
        print(f"tried: {args.config_dir}")
        return 0
    if args.verb in _SAFE_MESSAGE:
        # Default the confirmation window to 60s so an unattended box always self-reverts.
        window = parse_timeout(args.timeout) if args.timeout is not None else 60
        candidate = compile_config(args.config_dir)
        stopped = compile_stopped(args.config_dir)
        kept = safe_apply(candidate, stopped, timeout=window, confirm=prompt_confirm)
        if kept:
            # confirmed -> persist, unlike try (this is why apply is no longer the only saver).
            save_ruleset(candidate)
            print(f"{_SAFE_MESSAGE[args.verb]}: {args.config_dir}")
        else:
            print(f"reverted: {args.config_dir}")
        return 0
    if args.verb == "restore":
        restore_ruleset()
        print(f"restored: {DEFAULT_RULESET_PATH}")
        return 0
    if args.verb == "clear":
        clear_ruleset()
        print(f"cleared: {args.config_dir}")
        return 0
    # compile: emit the base inet ruleset as nftables JSON on stdout.
    print(json.dumps(compile_config(args.config_dir), indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except ShorewallNFError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
