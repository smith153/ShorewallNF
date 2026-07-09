"""Settings parser + frozen ``Settings`` IR model (ADR-0061, task #315).

``shorewallnf.conf`` is the optional, non-tabular global-settings file: a flat list of
``KEY=value`` assignments parsed by :func:`~shorewallnf.parser.parse_settings` into the frozen
:class:`~shorewallnf.ir.Settings` dataclass. It is never shell-sourced and does no variable
expansion; an unknown key or a malformed value fails fast (ADR-0004).
"""

from __future__ import annotations

import dataclasses

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import OnOffKeep, Settings, YesNoKeep
from shorewallnf.parser import parse_settings

# --- the Settings model ------------------------------------------------------


def test_settings_is_frozen_with_documented_defaults() -> None:
    s = Settings()
    assert s.ip_forwarding is OnOffKeep.KEEP
    assert s.log_martians is YesNoKeep.KEEP
    assert s.route_filter is YesNoKeep.KEEP
    assert isinstance(s.log_level, str) and s.log_level
    assert isinstance(s.logformat, str) and s.logformat
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.log_level = "debug"  # type: ignore[misc]


# --- absent file / absent key => defaults ------------------------------------


def test_empty_text_yields_all_defaults() -> None:
    assert parse_settings("") == Settings()


def test_absent_key_keeps_its_default() -> None:
    s = parse_settings("IP_FORWARDING=On\n")
    assert s.ip_forwarding is OnOffKeep.ON
    # every unset key keeps its default
    assert s == dataclasses.replace(Settings(), ip_forwarding=OnOffKeep.ON)


# --- the KEY=value grammar ---------------------------------------------------


def test_parses_every_in_scope_key() -> None:
    s = parse_settings(
        "LOG_LEVEL=warning\n"
        'LOGFORMAT="MyFW:%s:%s:"\n'
        "IP_FORWARDING=Off\n"
        "LOG_MARTIANS=Yes\n"
        "ROUTE_FILTER=No\n"
    )
    assert s == Settings(
        log_level="warning",
        logformat="MyFW:%s:%s:",
        ip_forwarding=OnOffKeep.OFF,
        log_martians=YesNoKeep.YES,
        route_filter=YesNoKeep.NO,
    )


def test_comments_and_blank_lines_are_ignored() -> None:
    s = parse_settings(
        "# a leading comment\n"
        "\n"
        "   \n"
        "IP_FORWARDING=On   # trailing comment\n"
        "  # indented comment\n"
        "LOG_MARTIANS=No\n"
    )
    assert s.ip_forwarding is OnOffKeep.ON
    assert s.log_martians is YesNoKeep.NO


def test_quotes_are_stripped_and_preserve_content() -> None:
    # double and single quotes both strip; they preserve surrounding whitespace and '#'.
    assert parse_settings('LOGFORMAT="  spaced  "\n').logformat == "  spaced  "
    assert parse_settings("LOGFORMAT='a#b:%s'\n").logformat == "a#b:%s"


def test_no_variable_expansion_dollar_is_literal() -> None:
    assert parse_settings('LOGFORMAT="$HOME:%s"\n').logformat == "$HOME:%s"


def test_enum_values_are_case_insensitive() -> None:
    assert parse_settings("IP_FORWARDING=keep\n").ip_forwarding is OnOffKeep.KEEP
    assert parse_settings("ROUTE_FILTER=YES\n").route_filter is YesNoKeep.YES


# --- fail fast: unknown keys -------------------------------------------------


def test_unknown_key_fails_fast_with_location() -> None:
    text = "IP_FORWARDING=On\nWIDGETS=42\n"
    with pytest.raises(ConfigError) as exc:
        parse_settings(text)
    assert exc.value.line == 2
    assert exc.value.path == "shorewallnf.conf"
    assert "WIDGETS" in str(exc.value)


def test_legacy_shorewall_conf_knob_fails_fast() -> None:
    # A knob valid in upstream shorewall.conf that ShorewallNF does not implement.
    with pytest.raises(ConfigError) as exc:
        parse_settings("STARTUP_ENABLED=Yes\n")
    assert "STARTUP_ENABLED" in str(exc.value)


def test_out_of_scope_adr_key_fails_fast() -> None:
    # An ADR-0061 key owned by a later epic (no consumer yet) is still unknown here.
    with pytest.raises(ConfigError) as exc:
        parse_settings("CLAMPMSS=Yes\n")
    assert "CLAMPMSS" in str(exc.value)


# --- fail fast: duplicate keys -----------------------------------------------


def test_duplicate_key_fails_fast_at_second_occurrence() -> None:
    # A repeated key must not silently last-win (ADR-0004 / ADR-0061 §4): it raises a
    # located ConfigError naming the offending key at the second occurrence.
    text = "IP_FORWARDING=On\nIP_FORWARDING=Off\n"
    with pytest.raises(ConfigError) as exc:
        parse_settings(text)
    assert exc.value.line == 2
    assert exc.value.path == "shorewallnf.conf"
    assert "IP_FORWARDING" in str(exc.value)


# --- fail fast: malformed values / lines -------------------------------------


def test_malformed_enum_value_fails_fast_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("LOG_MARTIANS=Maybe\n")
    assert exc.value.line == 1
    assert "LOG_MARTIANS" in str(exc.value)


def test_line_without_equals_is_malformed() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("IP_FORWARDING\n")
    assert exc.value.line == 1


def test_lowercase_key_is_malformed() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("ip_forwarding=On\n")
    assert exc.value.line == 1


def test_empty_key_is_malformed() -> None:
    with pytest.raises(ConfigError):
        parse_settings("=On\n")


def test_empty_log_level_is_malformed() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("LOG_LEVEL=\n")
    assert "LOG_LEVEL" in str(exc.value)


def test_over_length_logformat_is_out_of_range() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings(f'LOGFORMAT="{"x" * 200}"\n')
    assert "LOGFORMAT" in str(exc.value)
