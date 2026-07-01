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

from .errors import ShorewallNFError

_VERB_HELP = {
    "check": "preprocess and validate the config; emit no ruleset",
    "compile": "compile the config into an nftables ruleset",
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
    # Skeleton: the parse -> generate -> apply pipeline lands in later tasks/epics.
    # The verbs are wired and the error shell is live; compilation is not yet done.
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
