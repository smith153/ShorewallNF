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


_FIXTURE_DIR = str(Path(__file__).parent / "fixtures" / "preprocess_dir")


def test_check_verb_preprocesses_a_valid_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", _FIXTURE_DIR]) == 0
    assert "OK" in capsys.readouterr().out


def test_check_verb_reports_a_missing_config_dir(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "no-such-config-dir"]) == 1
    assert "error:" in capsys.readouterr().err


def test_error_shell_formats_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(args: object) -> int:
        raise ConfigError("unknown zone 'dmz'", path="rules", line=12)

    monkeypatch.setattr(cli, "_dispatch", boom)
    assert cli.main(["check", "myconfig"]) == 1
    assert "error: rules:12: unknown zone 'dmz'" in capsys.readouterr().err


_COMPILE_DIR = str(Path(__file__).parent / "fixtures" / "compile_dir")


def test_apply_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "apply" in capsys.readouterr().out


def test_apply_verb_checks_then_applies_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: calls.append("check"))
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: calls.append("apply"))
    assert cli.main(["apply", _COMPILE_DIR]) == 0
    assert calls == ["check", "apply"]
    assert _COMPILE_DIR in capsys.readouterr().out


def test_apply_verb_does_not_load_after_failed_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_check(_r: object) -> None:
        raise ConfigError("generated ruleset rejected by nft: boom")

    applied = False

    def record_apply(_r: object) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(cli, "check_ruleset", failing_check)
    monkeypatch.setattr(cli, "apply_ruleset", record_apply)
    assert cli.main(["apply", _COMPILE_DIR]) == 1
    assert applied is False
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("verb", ["start", "reload", "restart"])
def test_lifecycle_verb_in_help(verb: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert verb in capsys.readouterr().out


@pytest.mark.parametrize(
    ("verb", "message"),
    [("start", "started"), ("reload", "reloaded"), ("restart", "reloaded")],
)
def test_lifecycle_verb_checks_then_applies_and_exits_zero(
    verb: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: calls.append("check"))
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: calls.append("apply"))
    assert cli.main([verb, _COMPILE_DIR]) == 0
    assert calls == ["check", "apply"]
    out = capsys.readouterr().out
    assert message in out
    assert _COMPILE_DIR in out


@pytest.mark.parametrize("verb", ["start", "reload", "restart"])
def test_lifecycle_verb_does_not_load_after_failed_check(
    verb: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def failing_check(_r: object) -> None:
        raise ConfigError("generated ruleset rejected by nft: boom")

    applied = False

    def record_apply(_r: object) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(cli, "check_ruleset", failing_check)
    monkeypatch.setattr(cli, "apply_ruleset", record_apply)
    assert cli.main([verb, _COMPILE_DIR]) == 1
    assert applied is False
    assert "error:" in capsys.readouterr().err


def test_console_script_entry_point_declared() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert data["project"]["scripts"]["shorewallnf"] == "shorewallnf.cli:main"
