"""Preprocessor — the pure text→text stage between Reader and Parser.

Shorewall configs are shell-preprocessed before parsing: ``params`` variables are
substituted, ``?if``/``?FORMAT``/``?SECTION`` directives are resolved. This module owns
that stage as pure functions over immutable :class:`SourceLine` values (ADR-0003); the
Reader (imperative shell) supplies the raw text and source paths. Undefined variables and
malformed input fail fast with :class:`~shorewallnf.errors.ConfigError` carrying the
offending location. See docs/module-layout.md.

This task (params substitution) establishes the module and the ``SourceLine`` carrier;
``?if`` conditionals and ``?FORMAT``/``?SECTION`` land in later tasks on the same chain.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

from .errors import ConfigError

# A shell-style variable reference: ``$NAME`` or ``${NAME}``. Names are identifiers
# (letter/underscore, then word chars) — a bare ``$`` or ``$5`` is left untouched.
_VAR_REF = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_]\w*)\}|(?P<bare>[A-Za-z_]\w*))")


@dataclass(frozen=True, slots=True)
class SourceLine:
    """One physical config line tagged with where it came from, for error reporting."""

    text: str
    path: str
    line: int


def parse_params(text: str, *, path: str = "params") -> dict[str, str]:
    """Parse a Shorewall ``params`` file into a ``name -> value`` mapping.

    Blank lines and ``#`` comment lines are ignored; every other line must be
    ``NAME=value`` (value is taken literally, surrounding whitespace stripped). A line
    without ``=`` or with a non-identifier name raises :class:`ConfigError`.
    """
    params: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, sep, value = stripped.partition("=")
        name = name.strip()
        if not sep or not name.isidentifier():
            raise ConfigError(
                f"malformed params line (expected NAME=value): {raw!r}",
                path=path,
                line=lineno,
            )
        params[name] = value.strip()
    return params


def substitute(lines: Iterable[SourceLine], params: Mapping[str, str]) -> list[SourceLine]:
    """Substitute ``$VAR`` / ``${VAR}`` references in each line using ``params``.

    A reference to a name not in ``params`` raises :class:`ConfigError` carrying that
    line's source location. Source path/line are preserved on the returned lines.
    """
    return [replace(line, text=_substitute_text(line, params)) for line in lines]


def _substitute_text(line: SourceLine, params: Mapping[str, str]) -> str:
    def resolve(match: re.Match[str]) -> str:
        name = match["braced"] or match["bare"]
        try:
            return params[name]
        except KeyError:
            raise ConfigError(
                f"undefined variable ${name}", path=line.path, line=line.line
            ) from None

    return _VAR_REF.sub(resolve, line.text)
