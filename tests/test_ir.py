import dataclasses

import pytest

from shorewallnf.ir import Family, Ruleset, Zone


def test_zone_is_family_aware() -> None:
    zone = Zone(name="loc", family=Family.INET)
    assert zone.name == "loc"
    assert zone.family is Family.INET


def test_zone_is_frozen() -> None:
    zone = Zone(name="loc", family=Family.INET)
    attr = "name"  # variable avoids ruff B010 while still exercising immutability
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(zone, attr, "net")


def test_ruleset_holds_zones_immutably() -> None:
    ruleset = Ruleset(zones=(Zone("loc", Family.IPV4), Zone("net", Family.IPV6)))
    assert len(ruleset.zones) == 2
    assert isinstance(ruleset.zones, tuple)
    attr = "zones"  # variable avoids ruff B010
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(ruleset, attr, ())
