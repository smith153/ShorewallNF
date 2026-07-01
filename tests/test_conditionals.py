import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.preprocessor import SourceLine, resolve_conditionals


def _lines(*texts: str, path: str = "rules") -> list[SourceLine]:
    return [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, start=1)]


def _texts(lines: list[SourceLine]) -> list[str]:
    return [line.text for line in lines]


# --- branch selection --------------------------------------------------------


def test_if_true_keeps_body() -> None:
    out = resolve_conditionals(_lines("?if $DEBUG", "log rule", "?endif"), {"DEBUG": "1"})
    assert _texts(out) == ["log rule"]


def test_if_false_drops_body() -> None:
    out = resolve_conditionals(_lines("?if $DEBUG", "log rule", "?endif"), {"DEBUG": "0"})
    assert _texts(out) == []


def test_undefined_param_in_condition_is_falsy_not_error() -> None:
    out = resolve_conditionals(_lines("?if $NOPE", "x", "?endif"), {})
    assert _texts(out) == []


def test_if_else_picks_else_when_false() -> None:
    out = resolve_conditionals(
        _lines("?if $DEBUG", "a", "?else", "b", "?endif"), {"DEBUG": ""}
    )
    assert _texts(out) == ["b"]


def test_if_elsif_else_picks_first_true_branch() -> None:
    lines = _lines(
        "?if $A", "a", "?elsif $B", "b", "?else", "c", "?endif"
    )
    assert _texts(resolve_conditionals(lines, {"A": "0", "B": "1"})) == ["b"]
    assert _texts(resolve_conditionals(lines, {"A": "1", "B": "1"})) == ["a"]
    assert _texts(resolve_conditionals(lines, {"A": "0", "B": "0"})) == ["c"]


def test_equality_comparison() -> None:
    out = resolve_conditionals(
        _lines("?if $FW == yes", "keep", "?endif"), {"FW": "yes"}
    )
    assert _texts(out) == ["keep"]


def test_inequality_comparison() -> None:
    out = resolve_conditionals(
        _lines("?if $FW != yes", "keep", "?endif"), {"FW": "no"}
    )
    assert _texts(out) == ["keep"]


# --- nesting -----------------------------------------------------------------


def test_nested_outer_true_inner_false() -> None:
    lines = _lines(
        "?if $OUTER", "outer-a", "?if $INNER", "inner", "?endif", "outer-b", "?endif"
    )
    out = resolve_conditionals(lines, {"OUTER": "1", "INNER": "0"})
    assert _texts(out) == ["outer-a", "outer-b"]


def test_nested_outer_false_suppresses_inner_true() -> None:
    lines = _lines(
        "?if $OUTER", "?if $INNER", "inner", "?endif", "?endif"
    )
    out = resolve_conditionals(lines, {"OUTER": "0", "INNER": "1"})
    assert _texts(out) == []


# --- pass-through ------------------------------------------------------------


def test_lines_outside_conditionals_pass_through() -> None:
    out = resolve_conditionals(_lines("a", "b"), {})
    assert _texts(out) == ["a", "b"]


def test_non_conditional_directives_pass_through_when_active() -> None:
    out = resolve_conditionals(
        _lines("?if $ON", "?FORMAT 3", "data", "?endif"), {"ON": "1"}
    )
    assert _texts(out) == ["?FORMAT 3", "data"]


def test_kept_lines_preserve_source_location() -> None:
    out = resolve_conditionals(_lines("?if $ON", "data", "?endif"), {"ON": "1"})
    assert (out[0].path, out[0].line) == ("rules", 2)


# --- error handling ----------------------------------------------------------


def test_unterminated_if_raises_at_if_line() -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_conditionals(_lines("?if $ON", "data"), {"ON": "1"})
    assert exc.value.line == 1


def test_endif_without_if_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_conditionals(_lines("data", "?endif"), {})
    assert exc.value.line == 2


def test_else_without_if_raises() -> None:
    with pytest.raises(ConfigError):
        resolve_conditionals(_lines("?else"), {})


def test_elsif_after_else_raises() -> None:
    with pytest.raises(ConfigError):
        resolve_conditionals(
            _lines("?if $A", "a", "?else", "b", "?elsif $C", "c", "?endif"), {"A": "0"}
        )


def test_unsupported_condition_operator_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_conditionals(
            _lines("noise", "?if $A && __CAP", "x", "?endif"), {"A": "1"}
        )
    assert exc.value.line == 2
