import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.preprocessor import (
    SourceLine,
    resolve_format_section,
    to_source_lines,
)


def _lines(*texts: str, path: str = "rules") -> list[SourceLine]:
    return [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, start=1)]


# --- to_source_lines --------------------------------------------------------


def test_to_source_lines_numbers_from_one() -> None:
    out = to_source_lines("a\nb\nc", "rules")
    assert [(sl.text, sl.line, sl.path) for sl in out] == [
        ("a", 1, "rules"),
        ("b", 2, "rules"),
        ("c", 3, "rules"),
    ]


# --- resolve_format_section: validate + preserve ----------------------------


def test_valid_format_and_section_pass_through_unchanged() -> None:
    lines = _lines("?FORMAT 2", "?SECTION NEW", "ACCEPT net fw")
    assert resolve_format_section(lines) == lines


def test_format_requires_a_positive_integer() -> None:
    for bad in ("?FORMAT", "?FORMAT abc", "?FORMAT 0", "?FORMAT 2 3"):
        with pytest.raises(ConfigError):
            resolve_format_section(_lines(bad))


def test_section_requires_a_single_name() -> None:
    for bad in ("?SECTION", "?SECTION A B"):
        with pytest.raises(ConfigError):
            resolve_format_section(_lines(bad))


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_format_section(_lines("data", "?FORMAT x"))
    assert exc.value.line == 2


def test_case_insensitive_directive_keywords() -> None:
    lines = _lines("?format 2", "?section NEW")
    assert resolve_format_section(lines) == lines


def test_non_directive_lines_are_untouched() -> None:
    lines = _lines("net eth0 detect", "# a comment", "")
    assert resolve_format_section(lines) == lines
