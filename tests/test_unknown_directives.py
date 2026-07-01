import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.preprocessor import (
    SourceLine,
    preprocess_file,
    reject_unknown_directives,
)


def _lines(*texts: str, path: str = "rules") -> list[SourceLine]:
    return [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, start=1)]


# --- reject_unknown_directives ----------------------------------------------


def test_unknown_directive_rejected_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        reject_unknown_directives(_lines("net eth0", "?COMMENT some note"))
    assert exc.value.line == 2
    assert "?COMMENT" in str(exc.value)


def test_typo_of_a_known_directive_is_rejected() -> None:
    with pytest.raises(ConfigError):
        reject_unknown_directives(_lines("?FROMAT 2"))


def test_known_directives_pass_through() -> None:
    lines = _lines("?FORMAT 2", "?SECTION NEW", "?if $X", "?else", "?endif", "data")
    assert reject_unknown_directives(lines) == lines


def test_plain_data_passes_through() -> None:
    lines = _lines("ACCEPT net fw tcp 22", "# a comment", "")
    assert reject_unknown_directives(lines) == lines


# --- integrated into preprocess_file ----------------------------------------


def test_preprocess_file_rejects_unknown_directive() -> None:
    with pytest.raises(ConfigError) as exc:
        preprocess_file("?SET foo 1\n", "rules", {})
    assert "?SET" in str(exc.value)


def test_unknown_directive_in_dead_branch_is_not_flagged() -> None:
    # The ?COMMENT lives in a false ?if branch — conditionals drop it before the guard runs.
    text = "?if $ON\n?COMMENT keep me quiet\n?endif\n"
    assert preprocess_file(text, "rules", {"ON": "0"}) == []
