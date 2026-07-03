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


def test_unit_is_fail_closed() -> None:
    """A oneshot that does not swallow errors: a failed restore fails the unit (no ExecStart=-)."""
    service = _directives(UNIT.read_text())["Service"]
    assert "oneshot" in _values(service, "Type")
    for command in _values(service, "ExecStart"):
        assert not command.startswith("-"), "ExecStart=- swallows the failure (not fail-closed)"
