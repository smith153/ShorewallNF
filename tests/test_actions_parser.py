"""Parser for site-defined ``action.<Name>`` files → ``MacroDef``/``MacroRule`` IR (#182).

Reader→Parser stage only: a body row becomes a ``MacroRule`` (no source/dest — those come
from the call site per ADR-0020), and ``parse_config`` collects the defs into a name-keyed
registry the resolver (#184) consumes. No expansion/narrowing happens here.
"""

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, MacroDef, MacroRule
from shorewallnf.parser import Record, parse, parse_action, parse_config
from shorewallnf.preprocessor import SourceLine


def _records(*texts: str, path: str = "action.Test") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _one(text: str) -> MacroRule:
    (rule,) = parse_action("Test", _records(text)).body
    return rule


# --- well-formed bodies ------------------------------------------------------


def test_minimal_action_row() -> None:
    assert _one("ACCEPT - -") == MacroRule(action="ACCEPT")


@pytest.mark.parametrize("action", ["ACCEPT", "DROP", "REJECT"])
def test_builtin_verdict_actions(action: str) -> None:
    assert _one(f"{action} - -").action == action


def test_proto_and_dest_port() -> None:
    rule = _one("ACCEPT - - tcp 22")
    assert (rule.proto, rule.dport, rule.sport) == ("tcp", "22", None)


def test_source_port_column() -> None:
    rule = _one("ACCEPT - - udp 53 1024")
    assert (rule.proto, rule.dport, rule.sport) == ("udp", "53", "1024")


def test_dash_columns_are_none() -> None:
    rule = _one("ACCEPT - - - - 1024")  # no proto/dport, only sport
    assert (rule.proto, rule.dport, rule.sport) == (None, None, "1024")


def test_proto_lowercased() -> None:
    assert _one("ACCEPT - - TCP 22").proto == "tcp"


def test_ordered_body() -> None:
    macro = parse_action("Web", _records("ACCEPT - - tcp 80", "ACCEPT - - tcp 443"))
    assert macro == MacroDef(
        name="Web",
        body=(
            MacroRule(action="ACCEPT", proto="tcp", dport="80"),
            MacroRule(action="ACCEPT", proto="tcp", dport="443"),
        ),
    )


# --- family inference (ADR-0002; from proto only, source/dest are `-`) --------


def test_family_both_without_proto() -> None:
    assert _one("ACCEPT - -").family is Family.BOTH


def test_family_ipv4_from_icmp() -> None:
    assert _one("ACCEPT - - icmp").family is Family.IPV4


def test_family_ipv6_from_ipv6_icmp() -> None:
    assert _one("ACCEPT - - ipv6-icmp").family is Family.IPV6


def test_def_family_single_family_body() -> None:
    macro = parse_action("V4", _records("ACCEPT - - icmp", "DROP - - icmp"))
    assert macro.family is Family.IPV4


def test_def_family_mixed_body_is_both() -> None:
    macro = parse_action("Mix", _records("ACCEPT - - icmp", "ACCEPT - - ipv6-icmp"))
    assert macro.family is Family.BOTH


# --- fail-fast ---------------------------------------------------------------


def test_non_dash_source_fails() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_action("Test", _records("ACCEPT 192.0.2.0/24 -"))
    assert exc.value.path == "action.Test"
    assert exc.value.line == 1


def test_non_dash_dest_fails() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_action("Test", _records("ACCEPT - 198.51.100.5"))
    assert exc.value.line == 1


def test_unsupported_action_fails() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_action("Test", _records("Ping - -"))
    assert exc.value.line == 1


def test_short_row_fails() -> None:
    with pytest.raises(ConfigError):
        parse_action("Test", _records("ACCEPT"))


def test_trailing_columns_fail() -> None:
    with pytest.raises(ConfigError):
        parse_action("Test", _records("ACCEPT - - tcp 22 - extra"))


# --- registry assembly (parse_config) ----------------------------------------


def _stream(name: str, *texts: str) -> list[SourceLine]:
    return [SourceLine(text=t, path=name, line=i) for i, t in enumerate(texts, 1)]


def test_parse_config_collects_name_keyed_registry() -> None:
    ruleset = parse_config(
        {
            "action.Ping": _stream("action.Ping", "ACCEPT - - icmp"),
            "action.Web": _stream("action.Web", "ACCEPT - - tcp 80"),
        }
    )
    assert set(ruleset.actions) == {"Ping", "Web"}
    assert ruleset.actions["Web"].body == (
        MacroRule(action="ACCEPT", proto="tcp", dport="80"),
    )


def test_parse_config_registry_deterministic_order() -> None:
    ruleset = parse_config(
        {
            "action.Zeta": _stream("action.Zeta", "ACCEPT - -"),
            "action.Alpha": _stream("action.Alpha", "ACCEPT - -"),
        }
    )
    assert list(ruleset.actions) == ["Alpha", "Zeta"]


def test_parse_config_ignores_actions_index() -> None:
    # The `actions` index file is discovered but not parsed into a MacroDef here.
    ruleset = parse_config({"actions": _stream("actions", "Ping")})
    assert ruleset.actions == {}


def test_parse_config_no_actions_is_empty_registry() -> None:
    assert parse_config({}).actions == {}
