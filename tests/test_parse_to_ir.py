"""Demonstrates the parse-to-IR scaffold (#47) end to end.

The scaffold (`build_records` + `require_field`) lives in the parser; the small builders and
the family-mix validation hook below are *representative demonstrations* of how a per-file
parser (owned by a feature epic) plugs into it — not production parsers.
"""

import re

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Rule, Zone
from shorewallnf.parser import Record, build_records, parse, require_field
from shorewallnf.preprocessor import SourceLine


def _records(*texts: str, path: str = "rules") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


# --- a representative zone builder ------------------------------------------


def _build_zone(record: Record) -> Zone:
    return Zone(name=require_field(record, 0, "zone name"))


def test_scaffold_maps_records_to_typed_ir() -> None:
    zones = build_records(_records("net", "loc", "fw", path="zones"), _build_zone)
    assert [z.name for z in zones] == ["net", "loc", "fw"]
    assert all(isinstance(z, Zone) for z in zones)


# --- a representative rule builder + ADR-0002 family-mix validation hook ------


def _build_rule(record: Record) -> Rule:
    return Rule(
        action=require_field(record, 0, "action"),
        source=require_field(record, 1, "source"),
        dest=require_field(record, 2, "dest"),
        proto=record.fields[3] if len(record.fields) > 3 else None,
    )


_V4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")


def _literal_family(token: str) -> Family | None:
    if _V4.match(token):
        return Family.IPV4
    if ":" in token:  # a bare IPv6 literal (demo scope: bare literals, no zone:host)
        return Family.IPV6
    return None


def _reject_family_mix(rule: Rule, record: Record) -> None:
    families = {f for f in (_literal_family(rule.source), _literal_family(rule.dest)) if f}
    if Family.IPV4 in families and Family.IPV6 in families:
        raise ConfigError(
            "rule mixes IPv4 and IPv6 literals", path=record.path, line=record.line
        )


def test_representative_rules_parse_into_typed_ir() -> None:
    rules = build_records(
        _records("ACCEPT net fw tcp", "ACCEPT 203.0.113.0/24 fw", "ACCEPT 2001:db8::/32 fw"),
        _build_rule,
        _reject_family_mix,
    )
    assert [(r.action, r.source, r.dest, r.proto) for r in rules] == [
        ("ACCEPT", "net", "fw", "tcp"),
        ("ACCEPT", "203.0.113.0/24", "fw", None),
        ("ACCEPT", "2001:db8::/32", "fw", None),
    ]


def test_validation_hook_fails_fast_on_family_mix_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        build_records(
            _records("ok net fw", "ACCEPT 203.0.113.0/24 2001:db8::/32"),
            _build_rule,
            _reject_family_mix,
        )
    assert exc.value.line == 2


# --- scaffold error handling -------------------------------------------------


def test_require_field_missing_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        build_records(_records("ACCEPT", path="rules"), _build_rule)
    assert exc.value.path == "rules"
    assert exc.value.line == 1
    assert "source" in str(exc.value)


def test_build_records_without_validate_hook() -> None:
    zones = build_records(_records("dmz", path="zones"), _build_zone)
    assert zones == [Zone(name="dmz")]
