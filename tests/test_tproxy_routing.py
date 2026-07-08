"""Tests for the transparent-proxy local-delivery routing channel (task #293, ADR-0051 Part B).

``generate_tproxy_routing`` lowers TPROXY mangle rules into a :class:`TproxyRoutingArtifact` —
one ``local`` route + fwmark ``ip rule`` per family that has any TPROXY (not one per rule; all
tproxy rules share the reserved :data:`TPROXY_MARK` and :data:`TPROXY_TABLE_ID`). Family-scoped
(ADR-0002): v4 covers ``0.0.0.0/0``, v6 ``::/0``; the artifact family is never
:data:`Family.BOTH`. Pure ``IR → data``, no I/O.
"""

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.generator import generate_tproxy_routing
from shorewallnf.ir import (
    TPROXY_MARK,
    TPROXY_TABLE_ID,
    Family,
    MangleRule,
    Ruleset,
    TproxyRoutingArtifact,
)


def _tproxy(family: Family, port: int = 3128) -> MangleRule:
    return MangleRule(action="TPROXY", dest="fw", proto="tcp", dport="80",
                      port=port, family=family)


def test_no_tproxy_yields_empty() -> None:
    rs = Ruleset(mangle_rules=(MangleRule(action="MARK", mark=1, family=Family.IPV4),))
    assert generate_tproxy_routing(rs) == ()


def test_empty_ruleset_yields_empty() -> None:
    assert generate_tproxy_routing(Ruleset()) == ()


def test_single_family_yields_one_artifact() -> None:
    arts = generate_tproxy_routing(Ruleset(mangle_rules=(_tproxy(Family.IPV4),)))
    assert arts == (
        TproxyRoutingArtifact(
            table_id=TPROXY_TABLE_ID, fwmark=TPROXY_MARK, family=Family.IPV4
        ),
    )


def test_reserved_constants_are_injected() -> None:
    (art,) = generate_tproxy_routing(Ruleset(mangle_rules=(_tproxy(Family.IPV6),)))
    assert art.table_id == TPROXY_TABLE_ID == 0xFFFFFFFF
    assert art.fwmark == TPROXY_MARK == 0xFFFFFFFF
    assert art.family is Family.IPV6


def test_multiple_rules_one_family_dedupe_to_one() -> None:
    rs = Ruleset(mangle_rules=(
        _tproxy(Family.IPV4, port=3128),
        _tproxy(Family.IPV4, port=8080),
    ))
    assert generate_tproxy_routing(rs) == (
        TproxyRoutingArtifact(
            table_id=TPROXY_TABLE_ID, fwmark=TPROXY_MARK, family=Family.IPV4
        ),
    )


def test_dual_stack_yields_one_per_family_v4_before_v6() -> None:
    rs = Ruleset(mangle_rules=(_tproxy(Family.IPV6), _tproxy(Family.IPV4)))
    arts = generate_tproxy_routing(rs)
    assert [a.family for a in arts] == [Family.IPV4, Family.IPV6]


def test_family_is_never_both() -> None:
    rs = Ruleset(mangle_rules=(_tproxy(Family.IPV4), _tproxy(Family.IPV6)))
    for art in generate_tproxy_routing(rs):
        assert art.family in (Family.IPV4, Family.IPV6)


def test_both_family_tproxy_fails_closed() -> None:
    rs = Ruleset(mangle_rules=(_tproxy(Family.BOTH),))
    with pytest.raises(ConfigError, match="concrete family"):
        generate_tproxy_routing(rs)


def test_artifact_is_frozen() -> None:
    art = TproxyRoutingArtifact(
        table_id=TPROXY_TABLE_ID, fwmark=TPROXY_MARK, family=Family.IPV4
    )
    with pytest.raises(AttributeError):
        art.family = Family.IPV6  # type: ignore[misc]
