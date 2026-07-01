import dataclasses

import pytest

from shorewallnf.ir import Family, Ruleset, Zone, ZoneMember

# --- Family: reconciled with ADR-0002 (both/ipv4/ipv6, no INET) --------------


def test_family_uses_adr0002_scoping_values() -> None:
    assert {f.value for f in Family} == {"both", "ipv4", "ipv6"}


def test_family_has_no_inet_member() -> None:
    # ADR-0002 scopes constructs as both/ipv4/ipv6; "inet" is the nftables *output*
    # table family, not an IR value. The old stub's Family.INET is gone.
    assert not hasattr(Family, "INET")


# --- ZoneMember: family lives on membership (ADR-0002) -----------------------


def test_interface_membership_is_dual_by_default() -> None:
    member = ZoneMember(interface="eth0", family=Family.BOTH)
    assert member.interface == "eth0"
    assert member.host is None
    assert member.family is Family.BOTH


def test_host_membership_carries_a_single_family() -> None:
    member = ZoneMember(interface="eth0", host="10.0.0.0/8", family=Family.IPV4)
    assert member.host == "10.0.0.0/8"
    assert member.family is Family.IPV4


def test_zone_member_is_frozen() -> None:
    member = ZoneMember(interface="eth0", family=Family.BOTH)
    attr = "interface"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(member, attr, "eth1")


# --- Zone: one family-independent identity, family on its members ------------


def test_zone_has_no_family_attribute() -> None:
    zone = Zone(name="loc")
    assert not hasattr(zone, "family")


def test_zone_with_dual_interface_membership() -> None:
    zone = Zone(
        name="net",
        members=(
            ZoneMember(interface="eth0", family=Family.BOTH),
            ZoneMember(interface="eth1", family=Family.BOTH),
        ),
    )
    assert zone.name == "net"
    assert len(zone.members) == 2
    assert isinstance(zone.members, tuple)


def test_zone_with_single_family_host_entry() -> None:
    zone = Zone(
        name="net",
        members=(ZoneMember(interface="eth0", host="2001:db8::/32", family=Family.IPV6),),
    )
    (member,) = zone.members
    assert member.family is Family.IPV6


def test_zone_defaults_to_no_members() -> None:
    # The firewall zone ($FW) has no interface members — an empty zone is legal.
    assert Zone(name="fw").members == ()


def test_zone_is_frozen() -> None:
    zone = Zone(name="loc")
    attr = "name"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(zone, attr, "net")


# --- Ruleset -----------------------------------------------------------------


def test_ruleset_holds_zones_immutably() -> None:
    ruleset = Ruleset(zones=(Zone("loc"), Zone("net")))
    assert len(ruleset.zones) == 2
    assert isinstance(ruleset.zones, tuple)
    attr = "zones"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(ruleset, attr, ())
