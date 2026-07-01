import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.preprocessor import SourceLine, parse_params, substitute

# --- parse_params: reject unsupported shell forms explicitly (#63) -----------


def test_export_prefix_rejected_naming_the_form() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_params("export NET_IF=eth1\n")
    assert "export" in str(exc.value).lower()
    assert exc.value.line == 1


def test_export_as_a_plain_var_name_still_allowed() -> None:
    # `export=x` assigns a variable literally named "export" — not the shell export form.
    assert parse_params("export=x\n") == {"export": "x"}


def test_double_quoted_value_rejected() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_params('NET_OPTIONS="routefilter,norfc1918"\n')
    assert exc.value.line == 1


def test_single_quoted_value_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_params("A='b'\n")


def test_inline_comment_after_value_rejected() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_params("LOG=info   # level\n")
    assert exc.value.line == 1


def test_hash_without_preceding_whitespace_is_a_literal_value() -> None:
    # A `#` not preceded by whitespace is literal (shell semantics), not a comment.
    assert parse_params("TAG=a#b\n") == {"TAG": "a#b"}


def test_plain_assignment_still_parses() -> None:
    assert parse_params("NET_IF=eth1\n") == {"NET_IF": "eth1"}


# --- substitute: flag a malformed / unterminated ${...} reference (#63) -------


def _line(text: str) -> SourceLine:
    return SourceLine(text=text, path="interfaces", line=7)


def test_unterminated_brace_rejected_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        substitute([_line("dev ${IFB")], {"IFB": "ifb0"})
    assert (exc.value.path, exc.value.line) == ("interfaces", 7)


def test_invalid_braced_name_rejected() -> None:
    with pytest.raises(ConfigError):
        substitute([_line("x ${1BAD}")], {})


def test_valid_braced_reference_still_substitutes() -> None:
    out = substitute([_line("dev ${IFB}")], {"IFB": "ifb0"})
    assert out[0].text == "dev ifb0"
