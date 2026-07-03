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
    check_ruleset,
    clear_ruleset,
    restore_ruleset,
    save_ruleset,
)
from .errors import ShorewallNFError
from .generator import generate
from .parser import parse_config
from .preprocessor import SourceLine, parse_params, preprocess_file
from .resolver import resolve
from .validator import validate

_VERB_HELP = {
    "check": "preprocess and validate the config; emit no ruleset",
    "compile": "compile the config into an nftables ruleset",
    "apply": "compile, dry-run check, load the ruleset, then save it to disk",
    "start": "bring the firewall up: compile, dry-run check, then atomically load the ruleset",
    "reload": "compile, dry-run check, then atomically replace the running ruleset",
    "restart": "alias of reload: atomically replace the running ruleset",
    "clear": "remove all ShorewallNF tables, leaving traffic unfiltered",
    "restore": "reload the last persisted ruleset from disk, fail-closed",
}

# Verbs that operate on persisted/live state, not a config directory, take no positional.
_NO_CONFIG_VERBS = frozenset({"restore"})

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
    return {
        name: preprocess_file(reader.read_file(config_dir, name), name, params)
        for name in present
        if name != "params"
    }


def compile_config(config_dir: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Compile a config directory into the base ``inet`` nftables ruleset (JSON).

    The shell seam composing the whole pipeline: preprocess (I/O) → parse into the IR →
    resolve macros/actions → validate → generate. Returns the ``python3-nftables`` JSON the
    compile verb emits and the applier can dry-run load.
    """
    return generate(validate(resolve(parse_config(preprocess(config_dir)))))


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
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    if args.verb == "check":
        streams = preprocess(args.config_dir)
        lines = sum(len(s) for s in streams.values())
        print(f"OK: {args.config_dir}: {len(streams)} files, {lines} preprocessed lines")
        return 0
    if args.verb == "apply":
        ruleset = compile_config(args.config_dir)
        check_ruleset(ruleset)
        apply_ruleset(ruleset)
        save_ruleset(ruleset)
        print(f"applied: {args.config_dir}")
        return 0
    if args.verb in _LIFECYCLE_MESSAGE:
        ruleset = compile_config(args.config_dir)
        check_ruleset(ruleset)
        apply_ruleset(ruleset)
        print(f"{_LIFECYCLE_MESSAGE[args.verb]}: {args.config_dir}")
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
