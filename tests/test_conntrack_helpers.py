"""Tests for the built-in conntrack-helper registry (#219, ADR-0040).

The registry is a pure, name-keyed table of ``HelperDef`` values covering a small
documented subset: each entry carries a canonical L4 proto, default port(s), and a
family capability (``Family.IPV4`` for a v4-only helper, ``Family.BOTH`` for a
v6-capable one, ADR-0002). No lookup, narrowing, or capability detection lives here.
"""

import pytest

from shorewallnf.conntrack import BUILTIN_HELPERS
from shorewallnf.ir import Family, HelperCapabilities, HelperDef


def test_registry_is_a_name_keyed_mapping_of_helper_defs() -> None:
    assert BUILTIN_HELPERS, "expected at least one built-in helper"
    for name, helper in BUILTIN_HELPERS.items():
        assert isinstance(helper, HelperDef)
        assert helper.name == name


def test_registry_is_immutable() -> None:
    with pytest.raises(TypeError):
        BUILTIN_HELPERS["x"] = HelperDef(  # type: ignore[index]
            name="x", proto="tcp", ports=("1",), family_capability=Family.BOTH
        )


def test_family_capability_is_only_ipv4_or_both() -> None:
    """A helper is either v4-only or v6-capable — never scoped to IPv6 alone (ADR-0002)."""
    for helper in BUILTIN_HELPERS.values():
        assert helper.family_capability in (Family.IPV4, Family.BOTH)


def test_a_v6_capable_helper_entry() -> None:
    """FTP: control channel on TCP 21, v6-capable."""
    ftp = BUILTIN_HELPERS["ftp"]
    assert ftp.proto == "tcp"
    assert ftp.ports == ("21",)
    assert ftp.family_capability is Family.BOTH


def test_a_v4_only_helper_entry() -> None:
    """PPTP: control channel on TCP 1723, IPv4-only (kernel helper has no IPv6 support)."""
    pptp = BUILTIN_HELPERS["pptp"]
    assert pptp.proto == "tcp"
    assert pptp.ports == ("1723",)
    assert pptp.family_capability is Family.IPV4


def test_unknown_helper_name_is_detectable() -> None:
    assert "no-such-helper" not in BUILTIN_HELPERS


# --- capability-flag surface (AUTOHELPERS-equivalent, pure data) --------------


def test_capabilities_default_provides_nothing() -> None:
    caps = HelperCapabilities()
    assert not caps.provides("ftp")


def test_capabilities_provides_only_listed_helpers() -> None:
    caps = HelperCapabilities(available=frozenset({"ftp", "tftp"}))
    assert caps.provides("ftp")
    assert caps.provides("tftp")
    assert not caps.provides("pptp")
