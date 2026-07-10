"""Consistency guards for the packaged boot-time restore systemd unit (task #207).

A raw ``.service`` file has little runtime behaviour to exercise, so it is guarded the same
way the docs are: assert the directives that make it correct — that it invokes the ``restore``
verb, is ordered before the network comes up (no unprotected boot window), and is fail-closed
(a bad restore fails the unit rather than swallowing the error). See ADR-0030 and
docs/lifecycle.md.
"""

from __future__ import annotations

from pathlib import Path

from shorewallnf.cli import _NO_CONFIG_VERBS, _VERB_HELP

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / "packaging" / "systemd" / "shorewallnf-restore.service"
MAIN_UNIT = ROOT / "packaging" / "systemd" / "shorewallnf.service"
DEFAULT_CONFIG_DIR = "/etc/shorewallnf"


def _directives(text: str) -> dict[str, list[tuple[str, str]]]:
    """Parse a systemd unit into ``{section: [(key, value), ...]}`` (duplicate keys allowed)."""
    sections: dict[str, list[tuple[str, str]]] = {}
    current: list[tuple[str, str]] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], [])
            continue
        assert current is not None, f"directive before any [Section]: {line!r}"
        key, sep, value = line.partition("=")
        assert sep, f"not a key=value directive: {line!r}"
        current.append((key.strip(), value.strip()))
    return sections


def _values(section: list[tuple[str, str]], key: str) -> list[str]:
    return [value for name, value in section if name == key]


def test_unit_file_exists() -> None:
    assert UNIT.is_file(), f"missing packaged systemd unit: {UNIT}"


def test_unit_is_ordered_before_the_network() -> None:
    """Loaded before interfaces come up so there is no unprotected boot window (ADR-0030)."""
    unit = _directives(UNIT.read_text())["Unit"]
    assert "no" in _values(unit, "DefaultDependencies")
    assert "network-pre.target" in _values(unit, "Wants")
    assert "network-pre.target" in _values(unit, "Before")


def test_unit_invokes_the_restore_verb() -> None:
    """ExecStart runs ``shorewallnf restore`` — the verb the unit relies on must exist."""
    service = _directives(UNIT.read_text())["Service"]
    exec_starts = _values(service, "ExecStart")
    assert len(exec_starts) == 1, f"expected exactly one ExecStart, got {exec_starts}"
    command = exec_starts[0]
    assert command.split("/")[-1].split() == ["shorewallnf", "restore"], command
    # The invoked verb is a real, no-config CLI verb (unit ↔ code consistency).
    assert "restore" in _VERB_HELP
    assert "restore" in _NO_CONFIG_VERBS


def test_unit_does_not_pin_a_hardcoded_binary_path() -> None:
    """ExecStart carries no absolute install path — the binary resolves via systemd's
    executable search path, so a shipped unit is not tied to ``/usr/bin`` (ADR-0064)."""
    service = _directives(UNIT.read_text())["Service"]
    (command,) = _values(service, "ExecStart")
    binary = command.split()[0]
    assert not binary.startswith("/"), f"ExecStart pins an absolute binary path: {command!r}"
    assert binary == "shorewallnf", command


def test_unit_is_fail_closed() -> None:
    """A oneshot that does not swallow errors: a failed restore fails the unit (no ExecStart=-)."""
    service = _directives(UNIT.read_text())["Service"]
    assert "oneshot" in _values(service, "Type")
    for command in _values(service, "ExecStart"):
        assert not command.startswith("-"), "ExecStart=- swallows the failure (not fail-closed)"


# --- Main lifecycle unit: shorewallnf.service (task #393, ADR-0064 §4) ---------------------
#
# The main unit wraps the `start`/`stop` lifecycle verbs and is ordered *after* the restore
# unit so the two never fight: restore establishes a protected state pre-network, then the main
# service brings up the freshly compiled config at multi-user. Same directive-assertion guard
# style as the restore unit above.


def test_main_unit_file_exists() -> None:
    assert MAIN_UNIT.is_file(), f"missing packaged systemd unit: {MAIN_UNIT}"


def test_main_unit_is_ordered_after_the_restore_unit() -> None:
    """After=shorewallnf-restore.service — no double-apply race, no unprotected window (§4)."""
    unit = _directives(MAIN_UNIT.read_text())["Unit"]
    assert "shorewallnf-restore.service" in _values(unit, "After")


def test_main_unit_is_wanted_by_multi_user_target() -> None:
    """Started at multi-user.target, where the current config is compiled and applied (§4)."""
    install = _directives(MAIN_UNIT.read_text())["Install"]
    assert "multi-user.target" in _values(install, "WantedBy")


def test_main_unit_start_and_stop_invoke_the_lifecycle_verbs() -> None:
    """ExecStart/ExecStop run ``shorewallnf start`` / ``shorewallnf stop`` with a config dir."""
    service = _directives(MAIN_UNIT.read_text())["Service"]

    (start_command,) = _values(service, "ExecStart")
    assert start_command.split() == ["shorewallnf", "start", DEFAULT_CONFIG_DIR], start_command

    (stop_command,) = _values(service, "ExecStop")
    assert stop_command.split() == ["shorewallnf", "stop", DEFAULT_CONFIG_DIR], stop_command

    # The invoked verbs are real, config-taking CLI verbs (unit ↔ code consistency).
    for verb in ("start", "stop"):
        assert verb in _VERB_HELP
        assert verb not in _NO_CONFIG_VERBS


def test_main_unit_does_not_pin_a_hardcoded_binary_path() -> None:
    """ExecStart/ExecStop carry no absolute install path — the binary resolves via systemd's
    executable search path, so a shipped unit is not tied to ``/usr/bin`` (ADR-0064 §3)."""
    service = _directives(MAIN_UNIT.read_text())["Service"]
    for command in _values(service, "ExecStart") + _values(service, "ExecStop"):
        binary = command.split()[0]
        assert not binary.startswith("/"), f"pins an absolute binary path: {command!r}"
        assert binary == "shorewallnf", command


def test_main_unit_is_oneshot_remain_after_exit() -> None:
    """Type=oneshot + RemainAfterExit=yes so the service holds the applied config active (§4)."""
    service = _directives(MAIN_UNIT.read_text())["Service"]
    assert "oneshot" in _values(service, "Type")
    assert "yes" in _values(service, "RemainAfterExit")
