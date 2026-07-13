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


# ---- show zones / show policies: rendered from the compiled config IR (task #411) ----------

_POLICY_DIR = str(Path(__file__).parent / "fixtures" / "policy_compile_dir")


@pytest.mark.parametrize("obj", ["zones", "policies"])
def test_show_config_object_requires_config_dir(obj: str) -> None:
    # Unlike `show rules`, zones/policies render the config IR — config_dir is required.
    with pytest.raises(SystemExit) as exc:
        cli.main(["show", obj])
    assert exc.value.code == 2


@pytest.mark.parametrize("verb", ["show", "list", "ls"])
def test_show_zones_renders_from_config(verb: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([verb, "zones", _POLICY_DIR]) == 0
    out = capsys.readouterr().out
    assert "Zones" in out
    assert "Zone fw (firewall)" in out  # the memberless firewall zone
    assert "Zone net" in out


@pytest.mark.parametrize("verb", ["show", "list", "ls"])
def test_show_policies_renders_from_config(verb: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([verb, "policies", _POLICY_DIR]) == 0
    out = capsys.readouterr().out
    assert "Policies" in out
    assert "REJECT" in out
    assert "info" in out  # a policy carrying a log level


def test_show_zones_dispatch_identically(capsys: pytest.CaptureFixture[str]) -> None:
    outs = []
    for verb in ("show", "list", "ls"):
        assert cli.main([verb, "zones", _POLICY_DIR]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1] == outs[2]  # show/list/ls take the same code path


def test_show_policies_dispatch_identically(capsys: pytest.CaptureFixture[str]) -> None:
    outs = []
    for verb in ("show", "list", "ls"):
        assert cli.main([verb, "policies", _POLICY_DIR]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1] == outs[2]


def test_show_policies_empty_config_renders_empty_section(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A valid config declaring no policies renders an empty-but-valid section, not a crash.
    assert cli.main(["show", "policies", _COMPILE_DIR]) == 0
    out = capsys.readouterr().out
    assert "Policies" in out
    assert "(no policies" in out


def test_show_zones_malformed_config_fails_fast_one_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "zones").write_text("badzone notatype\n")
    assert cli.main(["show", "zones", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err  # a clean ADR-0004 message, not a stack trace


def test_show_zones_missing_config_dir_fails_fast(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["show", "zones", "no-such-config-dir"]) == 1
    assert "error:" in capsys.readouterr().err


# ---- show connections: live conntrack, read-only (task #412, ADR-0065) ---------------------

_CONN_FIXTURE = (
    "tcp 6 431999 ESTABLISHED src=192.0.2.2 dst=203.0.113.9 sport=54321 dport=443 "
    "src=203.0.113.9 dst=192.0.2.2 sport=443 dport=54321 [ASSURED] mark=0 use=1\n"
)


@pytest.mark.parametrize("verb", ["show", "list", "ls"])
def test_show_connections_renders_live_conntrack(
    verb: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_connections", lambda: _CONN_FIXTURE)
    assert cli.main([verb, "connections"]) == 0
    out = capsys.readouterr().out
    assert "Connections" in out
    assert "ESTABLISHED" in out
    assert "192.0.2.2" in out


def test_show_connections_list_ls_dispatch_identically(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_connections", lambda: _CONN_FIXTURE)
    outs = []
    for verb in ("show", "list", "ls"):
        assert cli.main([verb, "connections"]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1] == outs[2]  # exact same output — same code path


def test_show_connections_takes_no_config_dir_positional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Like `show rules`, connections reads live kernel state — a config dir is not accepted.
    monkeypatch.setattr(cli, "list_connections", lambda: _CONN_FIXTURE)
    with pytest.raises(SystemExit) as exc:
        cli.main(["show", "connections", "some-dir"])
    assert exc.value.code == 2  # unexpected positional -> argparse usage error


def test_show_connections_empty_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_connections", lambda: "")
    assert cli.main(["show", "connections"]) == 0  # empty-but-valid, exit 0
    out = capsys.readouterr().out
    assert "Connections" in out
    assert "(no tracked connections)" in out


def test_show_connections_missing_binary_fails_fast_one_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> str:
        raise ShorewallNFError("conntrack utility not found; install conntrack-tools")

    monkeypatch.setattr(cli, "list_connections", boom)
    assert cli.main(["show", "connections"]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err  # a clean ADR-0004 message, not a stack trace


# ---- show log: bounded tail of firewall journal lines (task #413, ADR-0065) ----------------

_LOG_FIXTURE = (
    "usb 1-1: new high-speed USB device number 4\n"
    "Shorewall:net-fw:DROP:IN=eth0 SRC=203.0.113.7 DST=192.0.2.1 PROTO=TCP DPT=23\n"
    "EXT4-fs (sda1): mounted filesystem\n"
    "Shorewall:fw-net:REJECT:OUT=eth0 SRC=192.0.2.1 DST=203.0.113.9 PROTO=TCP DPT=25\n"
)


@pytest.mark.parametrize("verb", ["show", "list", "ls"])
def test_show_log_renders_firewall_tail(
    verb: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_log", lambda: _LOG_FIXTURE)
    assert cli.main([verb, "log"]) == 0
    out = capsys.readouterr().out
    assert "Firewall log" in out
    assert "Shorewall:net-fw:DROP" in out
    assert "USB device" not in out  # non-firewall kernel noise is filtered out


def test_show_log_list_ls_dispatch_identically(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_log", lambda: _LOG_FIXTURE)
    outs = []
    for verb in ("show", "list", "ls"):
        assert cli.main([verb, "log"]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1] == outs[2]  # exact same output — same code path


def test_show_log_lines_override_caps_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = "".join(f"Shorewall:net-fw:DROP:seq={i}\n" for i in range(5))
    monkeypatch.setattr(cli, "list_log", lambda: output)
    assert cli.main(["show", "log", "-n", "2"]) == 0
    out = capsys.readouterr().out
    shown = [ln for ln in out.splitlines() if "seq=" in ln]
    assert len(shown) == 2
    assert "seq=4" in out and "seq=3" in out and "seq=2" not in out


def test_show_log_default_caps_at_twenty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = "".join(f"Shorewall:net-fw:DROP:seq={i}\n" for i in range(30))
    monkeypatch.setattr(cli, "list_log", lambda: output)
    assert cli.main(["show", "log"]) == 0
    out = capsys.readouterr().out
    shown = [ln for ln in out.splitlines() if "seq=" in ln]
    assert len(shown) == 20  # default bound


def test_show_log_takes_optional_config_dir_for_logformat(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # A config dir supplies LOGFORMAT; its prefix head drives which lines are firewall lines.
    (tmp_path / "shorewallnf.conf").write_text('LOGFORMAT="MyFW:%s:%s:"\n')
    output = "MyFW:net-fw:DROP:a\nShorewall:net-fw:DROP:b\n"
    monkeypatch.setattr(cli, "list_log", lambda: output)
    assert cli.main(["show", "log", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "MyFW:net-fw:DROP:a" in out
    assert "Shorewall:net-fw:DROP:b" not in out  # a different prefix isn't a firewall line here


def test_show_log_empty_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_log", lambda: "")
    assert cli.main(["show", "log"]) == 0  # empty-but-valid, exit 0
    out = capsys.readouterr().out
    assert "Firewall log" in out
    assert "(no firewall log messages)" in out


def test_show_log_missing_journal_fails_fast_one_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> str:
        raise ShorewallNFError("journalctl not found; systemd journal is required")

    monkeypatch.setattr(cli, "list_log", boom)
    assert cli.main(["show", "log"]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err  # a clean ADR-0004 message, not a stack trace


def test_show_log_is_read_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The show path touches no live/saved ruleset — only the read-only journal seam is invoked.
    monkeypatch.setattr(cli, "list_log", lambda: _LOG_FIXTURE)
    monkeypatch.setattr(
        cli, "apply_ruleset", lambda r: pytest.fail("show log must not apply a ruleset")
    )
    monkeypatch.setattr(
        cli, "save_ruleset", lambda r: pytest.fail("show log must not save a ruleset")
    )
    assert cli.main(["show", "log"]) == 0


# ---- status: short firewall state plus `-i` per-interface state (task #414) -----------------


def test_status_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "status" in capsys.readouterr().out


def test_status_short_reports_loaded(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "Firewall: loaded" in out


def test_status_short_reports_not_loaded_when_stopped_or_cleared(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", lambda: {"nftables": []})
    assert cli.main(["status"]) == 0  # graceful degradation, not a crash
    assert "Firewall: stopped or cleared" in capsys.readouterr().out


def test_status_short_takes_no_config_dir_positional() -> None:
    # The short state reads the live ruleset — no config dir is accepted.
    with pytest.raises(SystemExit) as exc:
        cli.main(["status", "some-dir"])
    assert exc.value.code == 2


def test_status_interfaces_reports_per_interface_state(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    monkeypatch.setattr(cli, "link_states", lambda: {"eth0": True, "eth1": False})
    assert cli.main(["status", "-i", _POLICY_DIR]) == 0
    out = capsys.readouterr().out
    assert "Firewall: loaded" in out
    assert "Interfaces" in out
    assert "eth0" in out and "eth1" in out


def test_status_interfaces_requires_a_config_dir() -> None:
    # `-i` takes the config dir as its value — omitting it is an argparse usage error.
    with pytest.raises(SystemExit) as exc:
        cli.main(["status", "-i"])
    assert exc.value.code == 2


def test_status_interfaces_degrades_when_stopped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "list_ruleset", lambda: {"nftables": []})
    monkeypatch.setattr(cli, "link_states", lambda: {})
    assert cli.main(["status", "-i", _POLICY_DIR]) == 0
    out = capsys.readouterr().out
    assert "Firewall: stopped or cleared" in out
    assert "Interfaces" in out  # IR interfaces still render, with live link state


# ---- dump: consolidated read-only diagnostic report (task #415, ADR-0065) ------------------


def _dump_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the read-only collection seams `dump` aggregates (no root needed)."""
    monkeypatch.setattr(cli, "list_ruleset", _running_fixture)
    monkeypatch.setattr(cli, "list_connections", lambda: _CONN_FIXTURE)
    monkeypatch.setattr(cli, "list_log", lambda: _LOG_FIXTURE)


def test_dump_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "dump" in capsys.readouterr().out


def test_dump_requires_a_config_dir() -> None:
    # dump needs the config dir for the IR sections (zones/policies) and LOGFORMAT.
    with pytest.raises(SystemExit) as exc:
        cli.main(["dump"])
    assert exc.value.code == 2


def test_dump_aggregates_all_five_sections(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _dump_boundaries(monkeypatch)
    assert cli.main(["dump", _POLICY_DIR]) == 0
    out = capsys.readouterr().out
    # each section delegates to its already-merged renderer — content from every source is present
    assert "Table: inet filter" in out  # ruleset (render_rules)
    assert "Zone net" in out  # zones (render_zones)
    assert "Policies" in out  # policies (render_policies)
    assert "Connections" in out and "ESTABLISHED" in out  # connections (render_connections)
    assert "Firewall log" in out and "Shorewall:net-fw:DROP" in out  # log (render_log)


def test_dump_sections_appear_in_documented_order(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _dump_boundaries(monkeypatch)
    assert cli.main(["dump", _POLICY_DIR]) == 0
    out = capsys.readouterr().out
    banners = ("Table: inet filter", "Zone net", "Policies", "Connections", "Firewall log")
    order = [out.index(b) for b in banners]
    assert order == sorted(order)  # ruleset -> zones -> policies -> connections -> log


def test_dump_section_degrades_independently(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _dump_boundaries(monkeypatch)

    def boom() -> str:
        raise ShorewallNFError("conntrack utility not found; install conntrack-tools")

    monkeypatch.setattr(cli, "list_connections", boom)
    assert cli.main(["dump", _POLICY_DIR]) == 0  # one failing section never aborts the report
    out = capsys.readouterr().out
    assert "Connections" in out and "install conntrack-tools" in out  # actionable in-section note
    assert "Table: inet filter" in out  # the other sections still render
    assert "Zone net" in out
    assert "Firewall log" in out


def test_dump_all_sections_fail_still_produces_a_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> str:
        raise ShorewallNFError("boundary unavailable")

    def boom_ir(*args: object, **kwargs: object) -> object:
        raise ShorewallNFError("config unreadable")

    monkeypatch.setattr(cli, "list_ruleset", boom)
    monkeypatch.setattr(cli, "list_connections", boom)
    monkeypatch.setattr(cli, "list_log", boom)
    monkeypatch.setattr(cli, "parse_config", boom_ir)  # the IR (zones/policies) source fails too
    assert cli.main(["dump", _POLICY_DIR]) == 0  # every section degrades, the report still prints
    out = capsys.readouterr().out
    for label in ("Ruleset", "Zones", "Policies", "Connections", "Firewall log"):
        assert label in out
    assert out.count("(unavailable") == 5  # each of the five sections degraded to a note
    assert "Traceback" not in out


def test_dump_is_read_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # dump invokes only list/render seams — never an applier mutation.
    _dump_boundaries(monkeypatch)

    def forbidden(*args: object) -> None:
        pytest.fail("dump must not mutate the ruleset")

    monkeypatch.setattr(cli, "apply_ruleset", forbidden)
    monkeypatch.setattr(cli, "save_ruleset", forbidden)
    monkeypatch.setattr(cli, "clear_ruleset", forbidden)
    assert cli.main(["dump", _POLICY_DIR]) == 0


# --- try DIR [timeout] verb: safe-apply with auto-revert (task #437, ADR-0067) ----------------


def test_try_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "try" in capsys.readouterr().out


def test_try_verb_compiles_and_safe_applies_without_timeout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(cli, "compile_config", lambda d: {"candidate": d})
    monkeypatch.setattr(cli, "compile_stopped", lambda d: {"stopped": d})

    def fake_safe_apply(candidate: Any, stopped: Any, *, timeout: int | None) -> None:
        seen.update(candidate=candidate, stopped=stopped, timeout=timeout)

    monkeypatch.setattr(cli, "safe_apply", fake_safe_apply)
    saved = False

    def record_save(*_a: Any, **_k: Any) -> None:
        nonlocal saved
        saved = True

    monkeypatch.setattr(cli, "save_ruleset", record_save)
    assert cli.main(["try", _COMPILE_DIR]) == 0
    assert seen["candidate"] == {"candidate": _COMPILE_DIR}
    assert seen["stopped"] == {"stopped": _COMPILE_DIR}
    assert seen["timeout"] is None
    assert saved is False  # try never persists (non-persisting, like start/reload)
    assert _COMPILE_DIR in capsys.readouterr().out


def test_try_verb_parses_and_passes_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(cli, "compile_config", lambda d: {})
    monkeypatch.setattr(cli, "compile_stopped", lambda d: {})
    monkeypatch.setattr(
        cli, "safe_apply", lambda c, s, *, timeout: seen.update(timeout=timeout)
    )
    assert cli.main(["try", _COMPILE_DIR, "5m"]) == 0
    assert seen["timeout"] == 300  # parse_timeout("5m") -> 300 seconds (#436)


def test_try_verb_rejects_a_bad_timeout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "compile_config", lambda d: {})
    monkeypatch.setattr(cli, "compile_stopped", lambda d: {})
    applied = False

    def fake_safe_apply(*_a: Any, **_k: Any) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(cli, "safe_apply", fake_safe_apply)
    assert cli.main(["try", _COMPILE_DIR, "nope"]) == 1
    assert applied is False  # fail fast before touching the firewall
    assert "error:" in capsys.readouterr().err


def test_try_verb_does_not_apply_or_persist_after_compile_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_d: object) -> dict[str, Any]:
        raise ConfigError("compile boom")

    monkeypatch.setattr(cli, "compile_config", boom)
    applied = False

    def fake_safe_apply(*_a: Any, **_k: Any) -> None:
        nonlocal applied
        applied = True

    monkeypatch.setattr(cli, "safe_apply", fake_safe_apply)
    saved = False

    def record_save(*_a: Any, **_k: Any) -> None:
        nonlocal saved
        saved = True

    monkeypatch.setattr(cli, "save_ruleset", record_save)
    assert cli.main(["try", _COMPILE_DIR]) == 1
    assert applied is False  # compile failure terminates before the safe-apply seam
    assert saved is False
    assert "error:" in capsys.readouterr().err
