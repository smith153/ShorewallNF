"""Tests for the built-in macro/action registry (#181, ADR-0020).

The registry is a pure, name-keyed mapping of ``MacroDef`` values covering a
small documented subset: each body is an ordered tuple of ``ACCEPT``/``DROP``/
``REJECT`` ``MacroRule`` templates, optionally narrowed by proto/dport/sport/
family. No lookup, narrowing, or verdict outside that set lives here.
"""

from shorewallnf.ir import Family, MacroDef, MacroRule
from shorewallnf.macros import BUILTIN_MACROS


def test_registry_is_a_name_keyed_mapping_of_macro_defs() -> None:
    assert BUILTIN_MACROS, "expected at least one built-in"
    for name, macro in BUILTIN_MACROS.items():
        assert isinstance(macro, MacroDef)
        assert macro.name == name


def test_registry_covers_at_least_one_macro_and_one_action() -> None:
    assert "Web" in BUILTIN_MACROS
    assert "DropSmb" in BUILTIN_MACROS


def test_web_macro_body() -> None:
    """Web is a port-group macro accepting HTTP and HTTPS, in order."""
    assert BUILTIN_MACROS["Web"].body == (
        MacroRule(action="ACCEPT", proto="tcp", dport="80"),
        MacroRule(action="ACCEPT", proto="tcp", dport="443"),
    )


def test_drop_smb_action_body() -> None:
    """DropSmb is a drop-noise action: DROPs SMB/NetBIOS ports, in order."""
    assert BUILTIN_MACROS["DropSmb"].body == (
        MacroRule(action="DROP", proto="udp", dport="137:139"),
        MacroRule(action="DROP", proto="udp", dport="445"),
        MacroRule(action="DROP", proto="tcp", dport="139"),
        MacroRule(action="DROP", proto="tcp", dport="445"),
    )


def test_every_body_line_is_a_builtin_verdict() -> None:
    verdicts = {"ACCEPT", "DROP", "REJECT"}
    for macro in BUILTIN_MACROS.values():
        for rule in macro.body:
            assert rule.action in verdicts


def test_registry_is_immutable() -> None:
    import pytest

    with pytest.raises(TypeError):
        BUILTIN_MACROS["X"] = MacroDef(name="X")  # type: ignore[index]


def test_definitions_default_to_both_families() -> None:
    for macro in BUILTIN_MACROS.values():
        assert macro.family is Family.BOTH
