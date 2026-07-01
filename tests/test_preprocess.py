from pathlib import Path

import pytest

from shorewallnf.cli import preprocess
from shorewallnf.errors import ConfigError
from shorewallnf.preprocessor import preprocess_file

FIXTURE = Path(__file__).parent / "fixtures" / "preprocess_dir"


# --- preprocess_file: the pure per-file pipeline -----------------------------


def test_preprocess_file_composes_conditionals_format_and_substitution() -> None:
    text = "?SECTION NEW\n?if $ENABLE\nACCEPT net fw tcp $PORT\n?else\nDROP net fw\n?endif\n"
    out = preprocess_file(text, "rules", {"ENABLE": "1", "PORT": "22"})
    assert [sl.text for sl in out] == ["?SECTION NEW", "ACCEPT net fw tcp 22"]


def test_preprocess_file_takes_else_branch_when_condition_false() -> None:
    text = "?if $ENABLE\nA\n?else\nB\n?endif\n"
    out = preprocess_file(text, "rules", {"ENABLE": "0"})
    assert [sl.text for sl in out] == ["B"]


def test_preprocess_file_substitutes_and_keeps_locations() -> None:
    out = preprocess_file("net $IF detect\n", "interfaces", {"IF": "eth0"})
    assert (out[0].text, out[0].path, out[0].line) == ("net eth0 detect", "interfaces", 1)


def test_preprocess_file_propagates_undefined_variable_error() -> None:
    with pytest.raises(ConfigError):
        preprocess_file("net $NOPE\n", "interfaces", {})


# --- preprocess(config_dir): the shell orchestration -------------------------


def test_preprocess_config_dir_runs_every_known_file() -> None:
    streams = preprocess(FIXTURE)
    assert set(streams) == {"interfaces", "rules"}  # params is consumed, not emitted
    assert [sl.text for sl in streams["interfaces"]] == ["?FORMAT 2", "net eth0 detect"]
    assert [sl.text for sl in streams["rules"]] == ["?SECTION NEW", "ACCEPT net fw tcp 22"]


def test_preprocess_missing_dir_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        preprocess(FIXTURE / "does-not-exist")
