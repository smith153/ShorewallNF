import tomllib
from pathlib import Path
from typing import Any

import pytest

from shorewallnf import cli
from shorewallnf.applier import DEFAULT_RULESET_PATH
from shorewallnf.errors import ConfigError, ShorewallNFError


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
_STOP_DIR = str(Path(__file__).parent / "fixtures" / "stop_compile_dir")


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
    monkeypatch.setattr(cli, "save_ruleset", lambda r: calls.append("save"))
    assert cli.main(["apply", _COMPILE_DIR]) == 0
    assert calls == ["check", "apply", "save"]
    assert _COMPILE_DIR in capsys.readouterr().out


def test_apply_verb_saves_the_exact_applied_ruleset(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    applied: list[object] = []
    saved: list[object] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: applied.append(r))
    monkeypatch.setattr(cli, "save_ruleset", lambda r: saved.append(r))
    assert cli.main(["apply", _COMPILE_DIR]) == 0
    # The persisted object is exactly the ruleset that was applied (round-trip guarantee).
    assert saved == applied


def test_apply_verb_does_not_save_after_failed_apply(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_apply(_r: object) -> None:
        raise ConfigError("ruleset rejected by nft: boom")

    saved = False

    def record_save(_r: object) -> None:
        nonlocal saved
        saved = True

    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", failing_apply)
    monkeypatch.setattr(cli, "save_ruleset", record_save)
    assert cli.main(["apply", _COMPILE_DIR]) == 1
    assert saved is False
    assert "error:" in capsys.readouterr().err


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


# ---- apply-time kernel sysctls threaded from shorewallnf.conf (task #322, ADR-0062) --------

_SYSCTL_DIR = str(Path(__file__).parent / "fixtures" / "sysctl_dir")


def test_apply_sets_sysctls_after_load_and_before_save(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: calls.append("check"))
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: calls.append("apply"))
    monkeypatch.setattr(cli, "apply_sysctls", lambda s: calls.append("sysctls"))
    monkeypatch.setattr(cli, "save_ruleset", lambda r: calls.append("save"))
    assert cli.main(["apply", _SYSCTL_DIR]) == 0
    # sysctls are mutated after the atomic nft load, and a failed sysctl step must precede save.
    assert calls == ["check", "apply", "sysctls", "save"]


def test_apply_threads_parsed_settings_to_apply_sysctls(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from shorewallnf.ir import OnOffKeep, Settings, YesNoKeep

    seen: list[Settings] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "save_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_sysctls", lambda s: seen.append(s))
    assert cli.main(["apply", _SYSCTL_DIR]) == 0
    # The Settings parsed from the config dir's shorewallnf.conf reach the applier verbatim.
    assert seen == [Settings(ip_forwarding=OnOffKeep.ON, log_martians=YesNoKeep.YES)]


def test_apply_does_not_save_after_failed_sysctls(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_sysctls(_s: object) -> None:
        raise ConfigError("sysctl net.ipv4.ip_forward=1 rejected: boom")

    saved = False

    def record_save(_r: object) -> None:
        nonlocal saved
        saved = True

    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_sysctls", failing_sysctls)
    monkeypatch.setattr(cli, "save_ruleset", record_save)
    assert cli.main(["apply", _SYSCTL_DIR]) == 1
    assert saved is False
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("verb", ["start", "reload", "restart"])
def test_lifecycle_verb_sets_sysctls_after_load(
    verb: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: calls.append("check"))
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: calls.append("apply"))
    monkeypatch.setattr(cli, "apply_sysctls", lambda s: calls.append("sysctls"))
    assert cli.main([verb, _SYSCTL_DIR]) == 0
    assert calls == ["check", "apply", "sysctls"]


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


def test_clear_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "clear" in capsys.readouterr().out


def test_clear_verb_invokes_clear_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "clear_ruleset", lambda: calls.append("clear"))
    assert cli.main(["clear", _COMPILE_DIR]) == 0
    assert calls == ["clear"]
    assert _COMPILE_DIR in capsys.readouterr().out


def test_clear_verb_reports_nft_rejection_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_clear() -> None:
        raise ConfigError("ruleset rejected by nft: boom")

    monkeypatch.setattr(cli, "clear_ruleset", failing_clear)
    assert cli.main(["clear", _COMPILE_DIR]) == 1
    assert "error:" in capsys.readouterr().err


# ---- stop verb: install the stopped safe state atomically (task #212, ADR-0021) ----------


def test_stop_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "stop" in capsys.readouterr().out


def test_stop_verb_checks_then_applies_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: calls.append("check"))
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: calls.append("apply"))
    assert cli.main(["stop", _COMPILE_DIR]) == 0
    # Dry-run check precedes the atomic load (fail-closed order).
    assert calls == ["check", "apply"]
    out = capsys.readouterr().out
    assert "stopped" in out
    assert _COMPILE_DIR in out


def test_stop_verb_installs_the_stopped_safe_state_not_the_running_ruleset(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # CLI/generation seam: `stop` compiles and loads the STOPPED safe state
    # (generate_stopped) — the admin-access stoppedrules, not the running config.
    applied: list[dict[str, Any]] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: applied.append(r))
    assert cli.main(["stop", _STOP_DIR]) == 0
    [ruleset] = applied
    assert ruleset == cli.compile_stopped(_STOP_DIR)
    # Dropping to the safe state is not "starting": with declared stoppedrules the stopped
    # state carries the admin rule while the running ruleset does not, so they differ.
    assert ruleset != cli.compile_config(_STOP_DIR)


def test_stop_with_no_admin_rules_still_admits_the_no_lockout_baseline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # compile_dir declares no stoppedrules, yet the stopped state the CLI loads still admits
    # the documented minimal baseline (no silent lockout) — asserted at the CLI seam.
    applied: list[dict[str, Any]] = []
    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", lambda r: applied.append(r))
    assert cli.main(["stop", _COMPILE_DIR]) == 0
    [ruleset] = applied
    accepts = [
        c
        for c in ruleset["nftables"]
        if "rule" in c.get("add", {}) and {"accept": None} in c["add"]["rule"]["expr"]
    ]
    assert accepts, "stopped state must admit baseline accepts even with zero admin rules"


def test_stop_verb_does_not_load_after_failed_check(
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
    assert cli.main(["stop", _COMPILE_DIR]) == 1
    assert applied is False
    assert "error:" in capsys.readouterr().err


def test_stop_verb_reports_apply_rejection_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A rejected stopped ruleset aborts fail-closed (the atomic load leaves prior state intact).
    def failing_apply(_r: object) -> None:
        raise ConfigError("ruleset rejected by nft: boom")

    monkeypatch.setattr(cli, "check_ruleset", lambda r: None)
    monkeypatch.setattr(cli, "apply_ruleset", failing_apply)
    assert cli.main(["stop", _COMPILE_DIR]) == 1
    assert "error:" in capsys.readouterr().err


def test_restore_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "restore" in capsys.readouterr().out


def test_restore_verb_takes_no_config_dir(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "restore_ruleset", lambda: calls.append("restore"))
    # No positional argument is required or accepted — restore reads the persisted path.
    assert cli.main(["restore"]) == 0
    assert calls == ["restore"]
    assert str(DEFAULT_RULESET_PATH) in capsys.readouterr().out


def test_restore_verb_rejects_a_positional_argument() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["restore", "some-config-dir"])
    assert exc.value.code == 2  # argparse usage error — restore takes no config_dir


def test_restore_verb_reports_failure_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_restore() -> None:
        raise ShorewallNFError("failed to read persisted ruleset")

    monkeypatch.setattr(cli, "restore_ruleset", failing_restore)
    assert cli.main(["restore"]) == 1
    assert "error:" in capsys.readouterr().err


def test_other_verbs_still_require_config_dir() -> None:
    # Relaxing the parser for restore must not drop the positional from config verbs.
    with pytest.raises(SystemExit) as exc:
        cli.main(["check"])
    assert exc.value.code == 2


def test_console_script_entry_point_declared() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert data["project"]["scripts"]["shorewallnf"] == "shorewallnf.cli:main"


# ---- read-only visibility: show / list / ls + `show rules` (task #410, ADR-0065) ----------

import json as _json  # noqa: E402


def _running_fixture() -> dict[str, object]:
    path = Path(__file__).parent / "fixtures" / "show_rules" / "running.json"
    data: dict[str, object] = _json.loads(path.read_text())
    return data


@pytest.mark.parametrize("verb", ["show", "list", "ls"])
def test_show_group_in_help(verb: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert verb in capsys.readouterr().out


@pytest.mark.parametrize("verb", ["show", "list", "ls"])
def test_show_rules_renders_live_ruleset(
    verb: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    assert cli.main([verb, "rules"]) == 0
    out = capsys.readouterr().out
    assert "Table: inet filter" in out
    assert "Chain input (policy drop)" in out
    assert "ACCEPT" in out


def test_show_list_ls_dispatch_identically(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    outs = []
    for verb in ("show", "list", "ls"):
        assert cli.main([verb, "rules"]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1] == outs[2]  # exact same output — same code path


def test_show_rules_takes_no_config_dir_positional(monkeypatch: pytest.MonkeyPatch) -> None:
    # Unlike every config verb, `show rules` reads the live ruleset — a config dir is not accepted
    # as the first token; positionals are chain names.
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)

    def fake_render(ruleset: object, *, table: str, chains: object) -> str:
        seen["table"] = table
        seen["chains"] = chains
        return "ok"

    monkeypatch.setattr(cli, "render_rules", fake_render)
    assert cli.main(["show", "rules", "input", "forward"]) == 0
    assert seen["chains"] == ("input", "forward")
    assert seen["table"] == "filter"  # default table


def test_show_rules_table_option(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    monkeypatch.setattr(
        cli, "render_rules", lambda r, *, table, chains: seen.setdefault("table", table) or "ok"
    )
    assert cli.main(["show", "rules", "-t", "nat"]) == 0
    assert seen["table"] == "nat"


def test_show_rules_rejects_unknown_table() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["show", "rules", "-t", "bogus"])
    assert exc.value.code == 2  # argparse choices usage error


def test_show_rules_bad_chain_fails_fast_one_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    assert cli.main(["show", "rules", "no-such-chain"]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err  # a clean message, not a stack trace


def test_show_rules_degrades_gracefully_when_firewall_stopped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", lambda: {"nftables": []})
    assert cli.main(["show", "rules"]) == 0  # empty-but-valid, exit 0
    assert "Table: inet filter" in capsys.readouterr().out


def test_show_requires_an_object() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["show"])
    assert exc.value.code == 2  # nested subparser required
