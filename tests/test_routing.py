"""Tests for the policy-routing artifact channel (epic #204, task #234, ADR-0050).

``generate_routing`` lowers each :class:`~shorewallnf.ir.Provider` into a
:class:`~shorewallnf.ir.RoutingArtifact` — a per-provider routing table (id = provider number,
default route via the gateway out its interface) together with the fwmark→table ``ip rule``.
Artifacts are family-scoped by the gateway literal (ADR-0002); a provider whose gateway is not an
address literal cannot be lowered and fails closed (ADR-0004).
"""

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.generator import generate_routing
from shorewallnf.ir import Family, Provider, RoutingArtifact, Ruleset
from tests.golden_harness import assert_golden

# A committed two-provider IPv4 set plus one IPv6-gateway provider (RFC 5737 / RFC 3849 only).
_ROUTING_RS = Ruleset(
    providers=(
        Provider(name="wan1", number=1, mark=1, interface="eth0",
                 gateway="192.0.2.1", family=Family.IPV4),
        Provider(name="wan2", number=2, mark=2, interface="eth1",
                 gateway="198.51.100.1", family=Family.IPV4),
        Provider(name="wan6", number=3, mark=3, interface="eth2",
                 gateway="2001:db8::1", family=Family.IPV6),
    )
)


def _routing_dict(ruleset: Ruleset) -> dict[str, list[dict[str, object]]]:
    return {
        "routing": [
            {
                "table_id": a.table_id,
                "fwmark": a.fwmark,
                "gateway": a.gateway,
                "interface": a.interface,
                "family": a.family.value,
            }
            for a in generate_routing(ruleset)
        ]
    }


def test_provider_routing_matches_golden() -> None:
    # The artifact model is not nftables JSON, so no nft --check — a plain golden diff.
    assert_golden(_ROUTING_RS, "providers_routing", check_nft=False, generator=_routing_dict)


def test_each_provider_lowers_to_a_table_and_fwmark_rule() -> None:
    arts = generate_routing(_ROUTING_RS)
    assert len(arts) == 3
    assert arts[0] == RoutingArtifact(
        table_id=1, fwmark=1, gateway="192.0.2.1", interface="eth0", family=Family.IPV4
    )


def test_ipv6_gateway_yields_a_v6_artifact() -> None:
    assert generate_routing(_ROUTING_RS)[2].family is Family.IPV6


def test_file_order_is_preserved() -> None:
    assert [a.table_id for a in generate_routing(_ROUTING_RS)] == [1, 2, 3]


def test_non_literal_gateway_fails_closed() -> None:
    rs = Ruleset(
        providers=(
            Provider(name="wanx", number=9, mark=9, interface="eth0",
                     gateway="detect", family=Family.BOTH),
        )
    )
    with pytest.raises(ConfigError, match="gateway"):
        generate_routing(rs)


def test_no_providers_yields_no_artifacts() -> None:
    assert generate_routing(Ruleset()) == ()
