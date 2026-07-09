import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Zone
from shorewallnf.parser import Record, parse, parse_zones
from shorewallnf.preprocessor import SourceLine


def _records(*texts: str, path: str = "zones") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def test_normal_zones_have_family_independent_names() -> None:
    zones = parse_zones(_records("net ipv4", "loc ipv4"))
    assert zones == (Zone(name="net"), Zone(name="loc"))
    assert all(not z.is_firewall for z in zones)


def test_firewall_zone_is_recognized() -> None:
    (fw,) = parse_zones(_records("fw firewall"))
    assert fw == Zone(name="fw", is_firewall=True)


def test_representative_zones_file() -> None:
    zones = parse_zones(_records("fw firewall", "net ipv4", "loc ipv4", "dmz ipv4"))
    assert [(z.name, z.is_firewall) for z in zones] == [
        ("fw", True),
        ("net", False),
        ("loc", False),
        ("dmz", False),
    ]


def test_ipv6_type_is_accepted_and_family_not_stored() -> None:
    # ADR-0002: the file's ipv4/ipv6 type does not put a family on the zone.
    (net,) = parse_zones(_records("net ipv6"))
    assert net == Zone(name="net")
    assert not hasattr(net, "family")


def test_unknown_zone_type_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_zones(_records("net ipv4", "loc bogus"))
    assert exc.value.line == 2
    assert "bogus" in str(exc.value)


def test_missing_zone_type_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_zones(_records("net"))
    assert exc.value.path == "zones"
    assert "type" in str(exc.value)


def test_duplicate_zone_raises_at_second_occurrence() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_zones(_records("net ipv4", "net ipv6"))
    assert exc.value.line == 2
    assert "net" in str(exc.value)


def test_parsed_zone_carries_source_location() -> None:
    # #316: located diagnostics — the parser stamps the row's path/line onto the IR.
    (zone,) = parse_zones(_records("net ipv4"))
    assert (zone.path, zone.line) == ("zones", 1)


def test_zone_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = Zone(name="net", path="zones", line=1)
    b = Zone(name="net", path="other", line=9)
    assert a == b
