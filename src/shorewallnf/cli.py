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
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import reader
from .applier import (
    DEFAULT_RULESET_PATH,
    apply_ruleset,
    apply_sysctls,
    check_ruleset,
    clear_ruleset,
    list_ruleset,
    restore_ruleset,
    save_ruleset,
)
from .errors import ShorewallNFError
from .generator import generate, generate_stopped
from .ir import Settings
from .parser import parse_config, parse_settings
from .preprocessor import SourceLine, parse_params, preprocess_file
from .renderer import render_rules
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
    return parser


def _add_show_group(sub: argparse._SubParsersAction[Any], verb: str) -> None:
    """Add a read-only visibility verb group (``show``/``list``/``ls``, ADR-0065).

    A *nested* subparser (verb -> object -> options), unlike the flat config verbs: its objects
    read the live ruleset, so they take no ``config_dir``. First object is ``rules``; the siblings
    (#411-#415) add more objects under this same group.
    """
    show_parser = sub.add_parser(verb, help="display live firewall state (read-only)")
    objects = show_parser.add_subparsers(dest="show_object", required=True)
    rules = objects.add_parser("rules", help="show the live packet-filter rules")
    rules.add_argument(
        "-t", "--table", choices=_SHOW_TABLES, default="filter", help="table to show"
    )
    rules.add_argument("chains", nargs="*", help="chains to show (default: all in the table)")


def _dispatch(args: argparse.Namespace) -> int:
    if args.verb in _SHOW_VERBS:
        # Read-only live query -> pure renderer (ADR-0065). list/ls dispatch identically to show.
        chains = tuple(args.chains) or None
        print(render_rules(list_ruleset(), table=args.table, chains=chains))
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
