"""Command-line entry point — the imperative shell.

Parses arguments, dispatches a verb, and is the single place a ``ShorewallNFError`` is
caught (ADR-0004): the pure core raises; the shell prints one clean message to stderr
and returns a non-zero exit code. See docs/adr/0004-error-handling.md and
docs/module-layout.md.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import reader
from .errors import ShorewallNFError
from .preprocessor import SourceLine, parse_params, preprocess_file

_VERB_HELP = {
    "check": "preprocess and validate the config; emit no ruleset",
    "compile": "compile the config into an nftables ruleset",
}


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shorewallnf",
        description="Compile a Shorewall-style config directory into nftables rules.",
    )
    sub = parser.add_subparsers(dest="verb", required=True)
    for verb, help_text in _VERB_HELP.items():
        verb_parser = sub.add_parser(verb, help=help_text)
        verb_parser.add_argument("config_dir", help="path to the Shorewall-style config directory")
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    if args.verb == "check":
        streams = preprocess(args.config_dir)
        lines = sum(len(s) for s in streams.values())
        print(f"OK: {args.config_dir}: {len(streams)} files, {lines} preprocessed lines")
        return 0
    # compile: parse -> generate -> apply lands in later epics; check is the live path.
    print(
        f"shorewallnf {args.verb}: {args.config_dir}: pipeline not yet implemented",
        file=sys.stderr,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except ShorewallNFError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
