import tomllib
from pathlib import Path

import pytest

from shorewallnf import cli
from shorewallnf.errors import ConfigError


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    assert "shorewallnf" in capsys.readouterr().out


def test_missing_verb_is_usage_error_exit_2() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_check_verb_dispatches(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "myconfig"]) == 0
    assert "myconfig" in capsys.readouterr().err


def test_error_shell_formats_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(args: object) -> int:
        raise ConfigError("unknown zone 'dmz'", path="rules", line=12)

    monkeypatch.setattr(cli, "_dispatch", boom)
    assert cli.main(["check", "myconfig"]) == 1
    assert "error: rules:12: unknown zone 'dmz'" in capsys.readouterr().err


def test_console_script_entry_point_declared() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert data["project"]["scripts"]["shorewallnf"] == "shorewallnf.cli:main"
