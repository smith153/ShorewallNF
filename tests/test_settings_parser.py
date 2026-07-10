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
from shorewallnf.ir import ClampMss, Disposition, OnOffKeep, Settings, YesNoKeep
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
        "LOG_LEVEL=notice\n"
        'LOGFORMAT="MyFW:%s:%s:"\n'
        "IP_FORWARDING=Off\n"
        "LOG_MARTIANS=Yes\n"
        "ROUTE_FILTER=No\n"
    )
    assert s == Settings(
        log_level="notice",
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


# --- CLAMPMSS: enum-or-int tri-state (ADR-0061, #368) ------------------------


def test_clampmss_defaults_off() -> None:
    # None (off) is the default, so an absent key and an explicit No both mean no clamp.
    assert Settings().clampmss is None
    assert parse_settings("").clampmss is None
    assert parse_settings("CLAMPMSS=No\n").clampmss is None


def test_clampmss_yes_is_path_mtu_sentinel() -> None:
    assert parse_settings("CLAMPMSS=Yes\n").clampmss is ClampMss.PATH_MTU


def test_clampmss_is_case_insensitive() -> None:
    assert parse_settings("CLAMPMSS=yes\n").clampmss is ClampMss.PATH_MTU
    assert parse_settings("CLAMPMSS=NO\n").clampmss is None


def test_clampmss_positive_integer_is_fixed_size() -> None:
    s = parse_settings("CLAMPMSS=1400\n")
    assert s.clampmss == 1400
    # a plain int, never a bool (bool ⊂ int in Python) — the three states stay distinct.
    assert type(s.clampmss) is int


@pytest.mark.parametrize("value", ["Maybe", "", "0", "-1", "14.0", "1400x", "0x10", "+5"])
def test_clampmss_malformed_value_fails_fast(value: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings(f"CLAMPMSS={value}\n")
    assert "CLAMPMSS" in str(exc.value)
    assert exc.value.line == 1


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
    # RPFILTER_*/TCP_FLAGS_*/SFILTER_* are now consumed (#380/#381/#382); the blacklist subsystem
    # keys (ADR-0061, its own future epic) are still unbuilt.
    with pytest.raises(ConfigError) as exc:
        parse_settings("BLACKLIST_DISPOSITION=DROP\n")
    assert "BLACKLIST_DISPOSITION" in str(exc.value)


# --- RPFILTER_DISPOSITION / RPFILTER_LOG_LEVEL (#380, ADR-0063) ---------------


def test_rpfilter_defaults_match_shorewall() -> None:
    # Shorewall's default disposition is DROP; no log unless a level is set (ADR-0063 §4).
    assert Settings().rpfilter_disposition is Disposition.DROP
    assert Settings().rpfilter_log_level is None
    assert parse_settings("").rpfilter_disposition is Disposition.DROP
    assert parse_settings("").rpfilter_log_level is None


@pytest.mark.parametrize(
    "value, disposition",
    [
        ("ACCEPT", Disposition.ACCEPT),
        ("DROP", Disposition.DROP),
        ("REJECT", Disposition.REJECT),
        ("CONTINUE", Disposition.CONTINUE),
        ("reject", Disposition.REJECT),  # case-insensitive
    ],
)
def test_rpfilter_disposition_parses(value: str, disposition: Disposition) -> None:
    assert parse_settings(f"RPFILTER_DISPOSITION={value}\n").rpfilter_disposition is disposition


def test_rpfilter_log_level_parses_and_defaults_none() -> None:
    assert parse_settings("RPFILTER_LOG_LEVEL=info\n").rpfilter_log_level == "info"


def test_rpfilter_bad_disposition_fails_fast() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("RPFILTER_DISPOSITION=MAYBE\n")
    assert "RPFILTER_DISPOSITION" in str(exc.value)


def test_rpfilter_bad_log_level_fails_fast() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("RPFILTER_LOG_LEVEL=warning\n")  # syslog spelling, not nft's `warn`
    assert "RPFILTER_LOG_LEVEL" in str(exc.value)


# --- TCP_FLAGS_DISPOSITION / TCP_FLAGS_LOG_LEVEL (#381, ADR-0063) -------------


def test_tcp_flags_defaults_match_shorewall() -> None:
    # Shorewall's default disposition is DROP; no log unless a level is set (ADR-0063 §2/§4).
    assert Settings().tcp_flags_disposition is Disposition.DROP
    assert Settings().tcp_flags_log_level is None
    assert parse_settings("").tcp_flags_disposition is Disposition.DROP
    assert parse_settings("").tcp_flags_log_level is None


@pytest.mark.parametrize(
    "value, disposition",
    [
        ("ACCEPT", Disposition.ACCEPT),
        ("DROP", Disposition.DROP),
        ("REJECT", Disposition.REJECT),
        ("CONTINUE", Disposition.CONTINUE),
        ("reject", Disposition.REJECT),  # case-insensitive
    ],
)
def test_tcp_flags_disposition_parses(value: str, disposition: Disposition) -> None:
    assert parse_settings(f"TCP_FLAGS_DISPOSITION={value}\n").tcp_flags_disposition is disposition


def test_tcp_flags_log_level_parses_and_defaults_none() -> None:
    assert parse_settings("TCP_FLAGS_LOG_LEVEL=info\n").tcp_flags_log_level == "info"


def test_tcp_flags_bad_disposition_fails_fast() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("TCP_FLAGS_DISPOSITION=MAYBE\n")
    assert "TCP_FLAGS_DISPOSITION" in str(exc.value)


def test_tcp_flags_bad_log_level_fails_fast() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("TCP_FLAGS_LOG_LEVEL=warning\n")  # syslog spelling, not nft's `warn`
    assert "TCP_FLAGS_LOG_LEVEL" in str(exc.value)


# --- SFILTER_DISPOSITION / SFILTER_LOG_LEVEL (#382, ADR-0063) -----------------


def test_sfilter_defaults_match_shorewall() -> None:
    # Shorewall's default disposition is DROP; no log unless a level is set (ADR-0063 §4/§5).
    assert Settings().sfilter_disposition is Disposition.DROP
    assert Settings().sfilter_log_level is None
    assert parse_settings("").sfilter_disposition is Disposition.DROP
    assert parse_settings("").sfilter_log_level is None


@pytest.mark.parametrize(
    "value, disposition",
    [
        ("ACCEPT", Disposition.ACCEPT),
        ("DROP", Disposition.DROP),
        ("REJECT", Disposition.REJECT),
        ("CONTINUE", Disposition.CONTINUE),
        ("reject", Disposition.REJECT),  # case-insensitive
    ],
)
def test_sfilter_disposition_parses(value: str, disposition: Disposition) -> None:
    assert parse_settings(f"SFILTER_DISPOSITION={value}\n").sfilter_disposition is disposition


def test_sfilter_log_level_parses_and_defaults_none() -> None:
    assert parse_settings("SFILTER_LOG_LEVEL=info\n").sfilter_log_level == "info"


def test_sfilter_bad_disposition_fails_fast() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("SFILTER_DISPOSITION=MAYBE\n")
    assert "SFILTER_DISPOSITION" in str(exc.value)


def test_sfilter_bad_log_level_fails_fast() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings("SFILTER_LOG_LEVEL=warning\n")  # syslog spelling, not nft's `warn`
    assert "SFILTER_LOG_LEVEL" in str(exc.value)


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


def test_unknown_log_level_keyword_fails_fast_with_location() -> None:
    # `warning` is a syslog spelling, not an nft log-level keyword (nft uses `warn`); it must
    # fail fast with the same file/line/key context as the tabular LOG LEVEL column (#367).
    with pytest.raises(ConfigError) as exc:
        parse_settings("IP_FORWARDING=On\nLOG_LEVEL=warning\n")
    assert exc.value.line == 2
    assert exc.value.path == "shorewallnf.conf"
    assert "LOG_LEVEL" in str(exc.value)


def test_over_length_logformat_is_out_of_range() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_settings(f'LOGFORMAT="{"x" * 200}"\n')
    assert "LOGFORMAT" in str(exc.value)


# --- DISABLE_IPV6: a plain Yes/No bool (#369) --------------------------------


def test_disable_ipv6_yes_no_parse_to_bool() -> None:
    assert parse_settings("DISABLE_IPV6=Yes\n").disable_ipv6 is True
    assert parse_settings("DISABLE_IPV6=No\n").disable_ipv6 is False


def test_disable_ipv6_is_case_insensitive() -> None:
    assert parse_settings("DISABLE_IPV6=yes\n").disable_ipv6 is True
    assert parse_settings("DISABLE_IPV6=NO\n").disable_ipv6 is False


def test_disable_ipv6_defaults_false_when_absent() -> None:
    assert Settings().disable_ipv6 is False
    assert parse_settings("").disable_ipv6 is False


def test_disable_ipv6_rejects_keep_tristate_value() -> None:
    # DISABLE_IPV6 is Yes/No only — no Keep (unlike LOG_MARTIANS/ROUTE_FILTER).
    with pytest.raises(ConfigError) as exc:
        parse_settings("DISABLE_IPV6=Keep\n")
    assert exc.value.line == 1
    assert "DISABLE_IPV6" in str(exc.value)
