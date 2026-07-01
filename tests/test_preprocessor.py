import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.preprocessor import SourceLine, parse_params, substitute

# --- parse_params -----------------------------------------------------------


def test_parse_params_basic_assignments() -> None:
    text = "LOG=info\nNET_IF=eth1\n"
    assert parse_params(text) == {"LOG": "info", "NET_IF": "eth1"}


def test_parse_params_ignores_comments_and_blank_lines() -> None:
    text = "# a comment\n\nNET_IF=eth1\n#LAST LINE - ADD ABOVE\n"
    assert parse_params(text) == {"NET_IF": "eth1"}


def test_parse_params_strips_surrounding_whitespace() -> None:
    assert parse_params("  NET_IF =  eth1  \n") == {"NET_IF": "eth1"}


def test_parse_params_malformed_line_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_params("LOG=info\nnot an assignment\n", path="params")
    assert exc.value.path == "params"
    assert exc.value.line == 2


def test_parse_params_invalid_name_raises() -> None:
    with pytest.raises(ConfigError):
        parse_params("1BAD=x\n")


# --- substitute -------------------------------------------------------------


def _line(text: str, line: int = 1, path: str = "interfaces") -> SourceLine:
    return SourceLine(text=text, path=path, line=line)


def test_substitute_bare_var() -> None:
    out = substitute([_line("net     $NET_IF   detect")], {"NET_IF": "eth1"})
    assert out == [_line("net     eth1   detect")]


def test_substitute_braced_var() -> None:
    out = substitute([_line("dev ${IFB_IF}")], {"IFB_IF": "ifb0"})
    assert out[0].text == "dev ifb0"


def test_substitute_multiple_vars_one_line() -> None:
    out = substitute([_line("$IFB_IF rate $NET_IF")], {"IFB_IF": "ifb0", "NET_IF": "eth1"})
    assert out[0].text == "ifb0 rate eth1"


def test_substitute_preserves_source_location() -> None:
    out = substitute([_line("$NET_IF", line=19, path="interfaces")], {"NET_IF": "eth1"})
    assert (out[0].path, out[0].line) == ("interfaces", 19)


def test_substitute_undefined_variable_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        substitute([_line("accept $FW", line=18, path="stoppedrules")], {"NET_IF": "eth1"})
    assert exc.value.path == "stoppedrules"
    assert exc.value.line == 18
    assert "FW" in str(exc.value)


def test_substitute_leaves_non_variable_dollar_untouched() -> None:
    out = substitute([_line("cost is $5 today")], {"NET_IF": "eth1"})
    assert out[0].text == "cost is $5 today"


def test_substitute_line_without_vars_unchanged() -> None:
    out = substitute([_line("loc eth0 detect")], {"NET_IF": "eth1"})
    assert out[0].text == "loc eth0 detect"
