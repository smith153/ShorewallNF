"""Preprocessor — the pure text→text stage between Reader and Parser.

Shorewall configs are shell-preprocessed before parsing: ``params`` variables are
substituted, ``?if``/``?FORMAT``/``?SECTION`` directives are resolved. This module owns
that stage as pure functions over immutable :class:`SourceLine` values (ADR-0003); the
Reader (imperative shell) supplies the raw text and source paths. Undefined variables and
malformed input fail fast with :class:`~shorewallnf.errors.ConfigError` carrying the
offending location. See docs/module-layout.md.

This module implements the full pure preprocessor chain — ``params`` substitution,
``?if``/``?elsif``/``?else``/``?endif`` conditionals, and ``?FORMAT``/``?SECTION`` validation —
composed per file by :func:`preprocess_file`. The imperative entry that reads a config
directory and runs this over each file lives in the shell (``cli.preprocess``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

from .errors import ConfigError

# A shell-style variable reference: ``$NAME`` or ``${NAME}``. Names are identifiers
# (letter/underscore, then word chars) — a bare ``$`` or ``$5`` is left untouched.
_VAR_REF = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_]\w*)\}|(?P<bare>[A-Za-z_]\w*))")

# A ``${`` not opening a well-formed ``${NAME}`` — unterminated or an invalid name. These
# would otherwise pass through silently, so we flag them instead of guessing.
_BAD_BRACE = re.compile(r"\$\{(?![A-Za-z_]\w*\})")

# An inline comment: whitespace followed by ``#`` (a ``#`` mid-token is a literal, per shell).
_INLINE_COMMENT = re.compile(r"\s#")


@dataclass(frozen=True, slots=True)
class SourceLine:
    """One physical config line tagged with where it came from, for error reporting."""

    text: str
    path: str
    line: int


def parse_params(text: str, *, path: str = "params") -> dict[str, str]:
    """Parse a Shorewall ``params`` file into a ``name -> value`` mapping.

    Blank lines and ``#`` comment lines are ignored; every other line must be a bare
    ``NAME=value`` (value taken literally, surrounding whitespace stripped). Shell forms a
    real ``params`` file may use but this does not yet support — an ``export`` prefix, a
    quoted value, or an inline comment — are **rejected with a message naming the form**
    rather than silently mis-parsed (they are absent from the MVP config subset; add support
    when a real config needs it). A line without ``=`` or with a non-identifier name also
    raises :class:`ConfigError`.
    """
    params: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, sep, value = stripped.partition("=")
        name = name.strip()
        fail = _params_error(name, sep, value)
        if fail is not None:
            raise ConfigError(fail, path=path, line=lineno)
        params[name] = value.strip()
    return params


def _params_error(name: str, sep: str, value: str) -> str | None:
    """Return the reason a ``NAME=value`` line is unacceptable, or ``None`` if it is fine."""
    if name.split()[:1] == ["export"] and len(name.split()) == 2:
        return "unsupported 'export' prefix in params (use NAME=value)"
    if not sep or not name.isidentifier():
        return f"malformed params line (expected NAME=value): {name + sep + value!r}"
    if value.strip()[:1] in ("'", '"'):
        return "unsupported quoted value in params"
    if _INLINE_COMMENT.search(value):
        return "unsupported inline comment in params"
    return None


def substitute(lines: Iterable[SourceLine], params: Mapping[str, str]) -> list[SourceLine]:
    """Substitute ``$VAR`` / ``${VAR}`` references in each line using ``params``.

    A reference to a name not in ``params``, or a malformed ``${...}`` (unterminated or an
    invalid name), raises :class:`ConfigError` carrying that line's source location. Source
    path/line are preserved on the returned lines.
    """
    return [replace(line, text=_substitute_text(line, params)) for line in lines]


def _substitute_text(line: SourceLine, params: Mapping[str, str]) -> str:
    if _BAD_BRACE.search(line.text):
        raise ConfigError("malformed ${...} reference", path=line.path, line=line.line)

    def resolve(match: re.Match[str]) -> str:
        name = match["braced"] or match["bare"]
        try:
            return params[name]
        except KeyError:
            raise ConfigError(
                f"undefined variable ${name}", path=line.path, line=line.line
            ) from None

    return _VAR_REF.sub(resolve, line.text)


_COND_KEYWORDS = frozenset({"?if", "?elsif", "?else", "?endif"})


@dataclass(slots=True)
class _CondFrame:
    """Bookkeeping for one open ``?if`` block while resolving conditionals."""

    parent_active: bool  # was the enclosing context emitting when this block opened?
    branch_active: bool  # is this block's current branch emitting?
    taken: bool  # has any branch in this block already been taken?
    seen_else: bool  # has ?else been seen (so a later ?elsif/?else is an error)?
    open_path: str  # location of the opening ?if, for the unterminated-block error
    open_line: int


def resolve_conditionals(
    lines: Iterable[SourceLine], params: Mapping[str, str]
) -> list[SourceLine]:
    """Resolve ``?if``/``?elsif``/``?else``/``?endif`` (including nesting), keeping only the
    lines in active branches.

    Conditions may reference ``params`` values: a single token is truthy when its resolved
    value is non-empty and not ``"0"``; ``A == B`` / ``A != B`` compare resolved values. An
    undefined variable resolves to empty (falsy), not an error. Anything richer (boolean
    operators, capability ``__symbols``) is unsupported and fails fast. Unbalanced or
    misplaced directives raise :class:`ConfigError`. Non-conditional lines (data, blanks, and
    other directives like ``?FORMAT``) pass through when their branch is active.
    """
    out: list[SourceLine] = []
    stack: list[_CondFrame] = []
    for source in lines:
        stripped = source.text.strip()
        parts = stripped.split(None, 1) if stripped else []
        keyword = parts[0].lower() if parts else ""
        if keyword not in _COND_KEYWORDS:
            if not stack or stack[-1].branch_active:
                out.append(source)
            continue
        rest = parts[1].strip() if len(parts) > 1 else ""

        if keyword == "?if":
            parent = not stack or stack[-1].branch_active
            active = parent and _eval_condition(keyword, rest, params, source)
            stack.append(
                _CondFrame(
                    parent_active=parent,
                    branch_active=active,
                    taken=active,
                    seen_else=False,
                    open_path=source.path,
                    open_line=source.line,
                )
            )
        elif keyword == "?elsif":
            frame = _require_frame(stack, source, keyword)
            if frame.seen_else:
                raise ConfigError("?elsif after ?else", path=source.path, line=source.line)
            frame.branch_active = (
                frame.parent_active
                and not frame.taken
                and _eval_condition(keyword, rest, params, source)
            )
            frame.taken = frame.taken or frame.branch_active
        elif keyword == "?else":
            frame = _require_frame(stack, source, keyword)
            if frame.seen_else:
                raise ConfigError("duplicate ?else", path=source.path, line=source.line)
            frame.branch_active = frame.parent_active and not frame.taken
            frame.taken = True
            frame.seen_else = True
        else:  # ?endif
            _require_frame(stack, source, keyword)
            stack.pop()

    if stack:
        frame = stack[-1]
        raise ConfigError(
            "unterminated ?if (missing ?endif)", path=frame.open_path, line=frame.open_line
        )
    return out


def _require_frame(
    stack: list[_CondFrame], source: SourceLine, keyword: str
) -> _CondFrame:
    if not stack:
        raise ConfigError(f"{keyword} without ?if", path=source.path, line=source.line)
    return stack[-1]


def _eval_condition(
    keyword: str, expr: str, params: Mapping[str, str], source: SourceLine
) -> bool:
    if not expr:
        raise ConfigError(f"{keyword} requires a condition", path=source.path, line=source.line)
    tokens = expr.split()
    if len(tokens) == 1:
        return _resolve_token(tokens[0], params) not in ("", "0")
    if len(tokens) == 3 and tokens[1] in ("==", "!="):
        left = _resolve_token(tokens[0], params)
        right = _resolve_token(tokens[2], params)
        return left == right if tokens[1] == "==" else left != right
    raise ConfigError(f"unsupported condition: {expr!r}", path=source.path, line=source.line)


def _resolve_token(token: str, params: Mapping[str, str]) -> str:
    # Condition context: an undefined variable resolves to empty (falsy), unlike substitute().
    return _VAR_REF.sub(lambda m: params.get(m["braced"] or m["bare"], ""), token)


def to_source_lines(text: str, path: str) -> list[SourceLine]:
    """Split raw file ``text`` into :class:`SourceLine`\\ s tagged with ``path`` and 1-based
    line numbers — the entry point that turns the Reader's text into the preprocessor stream.
    """
    return [SourceLine(text=t, path=path, line=i) for i, t in enumerate(text.splitlines(), 1)]


def resolve_format_section(lines: Iterable[SourceLine]) -> list[SourceLine]:
    """Validate ``?FORMAT n`` and ``?SECTION <NAME>`` directives, leaving lines unchanged.

    ``?FORMAT`` must carry a single positive integer; ``?SECTION`` a single name — otherwise
    :class:`ConfigError`. The directives are **preserved** in the stream (they mark
    format/section boundaries the per-file parsers act on later); the generic preprocessor
    only checks they are well-formed. Which format numbers or section names a given file
    actually allows is a per-file parser concern, not enforced here.
    """
    result = list(lines)
    for line in result:
        parts = line.text.split()
        keyword = parts[0].lower() if parts else ""
        if keyword == "?format" and not _is_positive_int_arg(parts):
            raise ConfigError(
                "?FORMAT requires a single positive integer", path=line.path, line=line.line
            )
        if keyword == "?section" and len(parts) != 2:
            raise ConfigError(
                "?SECTION requires a single section name", path=line.path, line=line.line
            )
    return result


def _is_positive_int_arg(parts: list[str]) -> bool:
    return len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= 1


# Every ``?``-directive the preprocessor understands. Anything else starting with ``?`` is a
# typo or an unsupported Shorewall directive — rejected rather than parsed as data.
_KNOWN_DIRECTIVES = _COND_KEYWORDS | {"?format", "?section"}


def reject_unknown_directives(lines: Iterable[SourceLine]) -> list[SourceLine]:
    """Fail fast on any line whose first token starts with ``?`` but is not a recognized
    directive, leaving all other lines unchanged.

    Run *after* conditional resolution so a directive dropped in an inactive ``?if`` branch is
    never seen. An unrecognized directive (a typo like ``?FROMAT``, or an unsupported one like
    ``?SET``/``?ERROR``) would otherwise pass through as config data — worse than refusing.
    """
    result = list(lines)
    for line in result:
        parts = line.text.split()
        token = parts[0] if parts else ""
        if token.startswith("?") and token.lower() not in _KNOWN_DIRECTIVES:
            raise ConfigError(f"unknown directive {token}", path=line.path, line=line.line)
    return result


def preprocess_file(text: str, path: str, params: Mapping[str, str]) -> list[SourceLine]:
    """Run the full pure per-file pipeline: split into lines, resolve ``?if`` conditionals,
    validate ``?FORMAT``/``?SECTION``, reject unknown ``?``-directives, then substitute
    ``params`` variables.
    """
    lines = to_source_lines(text, path)
    lines = resolve_conditionals(lines, params)
    lines = resolve_format_section(lines)
    lines = reject_unknown_directives(lines)
    return substitute(lines, params)
