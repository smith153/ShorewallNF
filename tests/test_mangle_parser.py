"""Tests for the ``mangle`` file parser (epic #203, task #228, ADR-0001/0002).

A ``mangle`` row is ``ACTION SOURCE DEST [PROTO] [DPORT]``. ``ACTION`` is a discriminated packet
-marking action — ``MARK(<value>[/<mask>])`` / ``CONNMARK(<value>[/<mask>])`` (set a packet/conn
mark, optional mask), ``DIVERT`` (bare), or ``TPROXY(<port>)`` (transparent-proxy to a
local port; the mark is the reserved ``TPROXY_MARK`` injected by the generator, not per-rule —
ADR-0051) — followed by the match criteria. Rows parse into family-aware
:class:`~shorewallnf.ir.MangleRule` IR preserving file order; the family follows the rule content
(ADR-0002). Unknown actions and malformed targets fail fast (ADR-0004). The generator is a sibling
task (#229).
"""

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, MangleRule
from shorewallnf.parser import Record, parse, parse_config, parse_mangle
from shorewallnf.preprocessor import SourceLine, to_source_lines


def _records(*texts: str, path: str = "mangle") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def _one(text: str) -> MangleRule:
    (rule,) = parse_mangle(_records(text))
    return rule


# --- MARK / CONNMARK ---------------------------------------------------------


def test_mark_sets_the_mark_value() -> None:
    assert _one("MARK(1) net loc") == MangleRule(
        action="MARK", source="net", dest="loc", mark=1
    )


def test_mark_with_mask() -> None:
    rule = _one("MARK(1/0xff) net loc")
    assert (rule.action, rule.mark, rule.mask) == ("MARK", 1, 255)


def test_connmark_sets_action_and_mark() -> None:
    rule = _one("CONNMARK(0x2) net loc")
    assert (rule.action, rule.mark, rule.mask) == ("CONNMARK", 2, None)


def test_mark_carries_match_criteria() -> None:
    rule = _one("MARK(1) net loc tcp 22")
    assert (rule.source, rule.dest, rule.proto, rule.dport) == ("net", "loc", "tcp", "22")


# --- DIVERT ------------------------------------------------------------------


def test_divert_has_no_parameters() -> None:
    assert _one("DIVERT net loc tcp") == MangleRule(
        action="DIVERT", source="net", dest="loc", proto="tcp"
    )


# --- TPROXY ------------------------------------------------------------------


def test_tproxy_sets_the_proxy_port() -> None:
    rule = _one("TPROXY(1080) net loc tcp 80")
    assert (rule.action, rule.port, rule.proto, rule.dport) == ("TPROXY", 1080, "tcp", "80")


def test_tproxy_carries_no_operator_mark() -> None:
    # ADR-0051 Part A: the mark is the reserved TPROXY_MARK injected by the generator, never a
    # per-rule operator value — so the parser attaches no mark for TPROXY.
    assert _one("TPROXY(1080) net loc tcp").mark is None


def test_tproxy_operator_mark_fails_fast() -> None:
    # A per-rule TPROXY(<port>,<mark>) is rejected: the tproxy mark is the compiler-reserved
    # TPROXY_MARK, not operator-supplied (ADR-0051 Part A / ADR-0004).
    with pytest.raises(ConfigError, match="reserved"):
        _one("TPROXY(1080,3) net loc tcp")


# --- family inference (ADR-0002) ---------------------------------------------


def test_family_defaults_to_both() -> None:
    assert _one("MARK(1) net loc").family is Family.BOTH


def test_v4_host_literal_narrows_family() -> None:
    assert _one("MARK(1) net loc:192.0.2.0/24").family is Family.IPV4


def test_v6_host_literal_narrows_family() -> None:
    assert _one("MARK(1) net loc:2001:db8::/32").family is Family.IPV6


# --- file order preserved ----------------------------------------------------


def test_file_order_is_preserved() -> None:
    rules = parse_mangle(
        _records(
            "MARK(1) net loc",
            "DIVERT net fw tcp",
            "TPROXY(1080) net loc tcp 80",
        )
    )
    assert [r.action for r in rules] == ["MARK", "DIVERT", "TPROXY"]


# --- fail fast (ADR-0004) ----------------------------------------------------


def test_unknown_action_fails_fast() -> None:
    with pytest.raises(ConfigError, match="unsupported mangle action"):
        _one("REDIRECT net loc")


def test_tproxy_non_integer_port_fails_fast() -> None:
    with pytest.raises(ConfigError, match="port"):
        _one("TPROXY(notaport) net loc tcp")


def test_tproxy_port_out_of_range_fails_fast() -> None:
    with pytest.raises(ConfigError, match="range"):
        _one("TPROXY(99999) net loc tcp")


def test_mark_without_a_value_fails_fast() -> None:
    with pytest.raises(ConfigError, match="MARK"):
        _one("MARK() net loc")


def test_mark_non_integer_value_fails_fast() -> None:
    with pytest.raises(ConfigError, match="integer"):
        _one("MARK(x) net loc")


def test_unsupported_trailing_columns_fail_fast() -> None:
    with pytest.raises(ConfigError, match="trailing"):
        _one("MARK(1) net loc tcp 22 1024")


def test_error_carries_source_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_mangle(_records("MARK(1) net loc", "BOGUS net loc"))
    assert exc.value.line == 2
    assert exc.value.path == "mangle"


# --- parse_config wiring -----------------------------------------------------


def test_parse_config_carries_mangle_rules_into_the_ruleset() -> None:
    ruleset = parse_config({"mangle": to_source_lines("MARK(1) net loc\n", "mangle")})
    assert ruleset.mangle_rules == (
        MangleRule(action="MARK", source="net", dest="loc", mark=1),
    )


def test_parsed_mangle_rule_carries_source_location() -> None:
    # #251: located diagnostics — the parser stamps the row's path/line onto the IR.
    rule = _one("MARK(1) net loc")
    assert (rule.path, rule.line) == ("mangle", 1)
