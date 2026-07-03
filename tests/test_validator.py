"""Validator stage tests (#138): dead ESTABLISHED/RELATED DROP/REJECT rules fail fast.

ADR-0005's base chains accept ``ct state {established, related}`` at the top of
``input``/``forward``. A rule in the ESTABLISHED or RELATED ``?SECTION`` is gated on that
same state but emitted *after* the base accept, so a ``DROP``/``REJECT`` there is
unreachable (dead). The Validator rejects it with an actionable, located-by-content error
(fail-closed). An ``ACCEPT`` there is a redundant no-op and is allowed; INVALID/NEW are
unaffected (their states are not in the base accept).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewallnf import cli
from shorewallnf.errors import ConfigError
from shorewallnf.ir import Interface, Provider, Rule, Ruleset
from shorewallnf.validator import validate


def _rs(action: str, section: str | None) -> Ruleset:
    return Ruleset(rules=(Rule(action=action, source="net", dest="loc", section=section),))


# --- the shadowed sections reject DROP/REJECT --------------------------------


@pytest.mark.parametrize("section", ["ESTABLISHED", "RELATED"])
@pytest.mark.parametrize("action", ["DROP", "REJECT"])
def test_drop_or_reject_in_shadowed_section_fails_fast(action: str, section: str) -> None:
    with pytest.raises(ConfigError) as exc:
        validate(_rs(action, section))
    msg = str(exc.value)
    assert action in msg  # names the offending action
    assert section in msg  # names the section
    assert "ADR-0005" in msg  # names the base-accept shadow


def test_shadowed_section_error_cites_path_line() -> None:
    # #195: when the offending rule carries a source location, the error prefixes path:line.
    rule = Rule(action="DROP", source="net", dest="loc", section="ESTABLISHED",
                path="rules", line=12)
    with pytest.raises(ConfigError) as exc:
        validate(Ruleset(rules=(rule,)))
    assert str(exc.value).startswith("rules:12: ")


def test_message_is_actionable() -> None:
    msg = _message(_rs("DROP", "ESTABLISHED")).lower()
    assert "unreachable" in msg or "dead" in msg
    assert "base chain" in msg


def test_shadowed_section_check_is_case_insensitive() -> None:
    with pytest.raises(ConfigError):
        validate(_rs("DROP", "established"))


# --- allowed cases -----------------------------------------------------------


@pytest.mark.parametrize("section", ["ESTABLISHED", "RELATED"])
def test_accept_in_shadowed_section_is_a_noop(section: str) -> None:
    rs = _rs("ACCEPT", section)
    assert validate(rs) is rs  # allowed; returns the ruleset unchanged


@pytest.mark.parametrize("section", ["INVALID", "NEW", None])
@pytest.mark.parametrize("action", ["DROP", "REJECT"])
def test_drop_or_reject_outside_shadowed_sections_is_allowed(
    action: str, section: str | None
) -> None:
    rs = _rs(action, section)
    assert validate(rs) is rs  # INVALID/NEW/unsectioned are unaffected


def test_empty_ruleset_validates() -> None:
    rs = Ruleset()
    assert validate(rs) is rs


# --- wired into the compile pipeline -----------------------------------------


def _config(tmp_path: Path, rules: str) -> Path:
    (tmp_path / "zones").write_text("fw firewall\nnet ipv4\nloc ipv4\n")
    (tmp_path / "interfaces").write_text("net eth0 detect\nloc eth1 detect\n")
    (tmp_path / "policy").write_text("all all DROP\n")
    (tmp_path / "rules").write_text(rules)
    return tmp_path


def test_compile_rejects_drop_in_established_section(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "?SECTION ESTABLISHED\nDROP net loc\n")
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    assert "ESTABLISHED" in str(exc.value)


def test_compile_allows_accept_in_established_section(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "?SECTION ESTABLISHED\nACCEPT net loc\n")
    cli.compile_config(cfg)  # redundant no-op; must not raise


def test_compile_allows_drop_in_invalid_section(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "?SECTION INVALID\nDROP net loc\n")
    cli.compile_config(cfg)  # unaffected; must not raise


def _message(rs: Ruleset) -> str:
    with pytest.raises(ConfigError) as exc:
        validate(rs)
    return str(exc.value)


# --- provider definitions: duplicate mark / table id / unknown interface (#233) ---

_ETH = (Interface(name="eth0"), Interface(name="eth1"))


def _providers_rs(*providers: Provider) -> Ruleset:
    return Ruleset(providers=providers, interfaces=_ETH)


def test_valid_provider_set_passes_unchanged() -> None:
    rs = _providers_rs(
        Provider(name="wan1", number=1, mark=1, interface="eth0", gateway="192.0.2.1"),
        Provider(name="wan2", number=2, mark=2, interface="eth1", gateway="198.51.100.1"),
    )
    assert validate(rs) is rs  # pure IR -> IR, no mutation


def test_duplicate_fwmark_fails_fast() -> None:
    msg = _message(
        _providers_rs(
            Provider(name="wan1", number=1, mark=1, interface="eth0", gateway="192.0.2.1"),
            Provider(name="wan2", number=2, mark=1, interface="eth1", gateway="198.51.100.1"),
        )
    )
    assert "fwmark" in msg and "wan1" in msg and "wan2" in msg  # names the collision


def test_duplicate_provider_number_fails_fast() -> None:
    msg = _message(
        _providers_rs(
            Provider(name="wan1", number=1, mark=1, interface="eth0", gateway="192.0.2.1"),
            Provider(name="wan2", number=1, mark=2, interface="eth1", gateway="198.51.100.1"),
        )
    )
    assert "wan1" in msg and "wan2" in msg and "1" in msg  # names both and the shared table id


def test_unknown_interface_fails_fast() -> None:
    msg = _message(
        _providers_rs(
            Provider(name="wan1", number=1, mark=1, interface="eth9", gateway="192.0.2.1"),
        )
    )
    assert "wan1" in msg and "eth9" in msg  # names the provider and the unknown interface


def test_provider_validation_error_cites_source_location() -> None:
    # #251: a Provider carrying path/line yields a located ConfigError (mirrors Rule, #198/#195).
    rs = Ruleset(
        providers=(
            Provider(name="wan1", number=1, mark=1, interface="eth0",
                     gateway="192.0.2.1", path="providers", line=3),
            Provider(name="wan2", number=2, mark=1, interface="eth1",
                     gateway="198.51.100.1", path="providers", line=4),
        ),
        interfaces=_ETH,
    )
    # The collision fires on the second (line 4) provider, so the error prefixes providers:4.
    assert str(_message(rs)).startswith("providers:4: ")
