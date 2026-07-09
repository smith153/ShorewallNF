import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Interface, Zone, ZoneMember
from shorewallnf.parser import Record, parse, parse_interfaces
from shorewallnf.preprocessor import SourceLine

_ZONES = (Zone(name="net"), Zone(name="loc"), Zone(name="fw", is_firewall=True))


def _records(*texts: str, path: str = "interfaces") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def test_maps_device_and_attaches_dual_stack_membership() -> None:
    result = parse_interfaces(_records("net eth0 detect"), _ZONES)
    assert result.interfaces == (Interface(name="eth0"),)
    net = next(z for z in result.zones if z.name == "net")
    assert net.members == (ZoneMember(interface="eth0", family=Family.BOTH),)


def test_parses_comma_separated_options() -> None:
    result = parse_interfaces(_records("net eth0 detect tcpflags,dhcp,nosmurfs"), _ZONES)
    assert result.interfaces[0].options == ("tcpflags", "dhcp", "nosmurfs")


def test_interface_without_options() -> None:
    result = parse_interfaces(_records("net eth0"), _ZONES)
    assert result.interfaces[0] == Interface(name="eth0", options=())


def test_dash_zone_means_no_membership() -> None:
    # Shorewall uses "-" for an interface in no zone (e.g. an ifb device).
    result = parse_interfaces(_records("- ifb0"), _ZONES)
    assert result.interfaces == (Interface(name="ifb0"),)
    assert all(z.members == () for z in result.zones)


def test_unknown_zone_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_interfaces(_records("net eth0", "bogus eth1"), _ZONES)
    assert exc.value.line == 2
    assert "bogus" in str(exc.value)


def test_missing_interface_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_interfaces(_records("net"), _ZONES)
    assert "interface" in str(exc.value)


def test_directive_rows_are_not_interfaces_and_format2_drops_broadcast() -> None:
    # ?FORMAT survives preprocessing as a record: it configures columns (FORMAT 2 has no
    # BROADCAST column, so OPTIONS is field 2) and is not itself an interface entry.
    result = parse_interfaces(_records("?FORMAT 2", "net eth0 tcpflags,dhcp"), _ZONES)
    assert result.interfaces == (Interface(name="eth0", options=("tcpflags", "dhcp")),)


def test_format1_default_keeps_broadcast_column() -> None:
    # No ?FORMAT → FORMAT 1: ZONE INTERFACE BROADCAST OPTIONS, so "detect" is the BROADCAST
    # value (ignored) and OPTIONS is field 3.
    result = parse_interfaces(_records("net eth0 detect tcpflags,dhcp"), _ZONES)
    assert result.interfaces == (Interface(name="eth0", options=("tcpflags", "dhcp")),)


def test_unsupported_format_for_interfaces_raises() -> None:
    with pytest.raises(ConfigError):
        parse_interfaces(_records("?FORMAT 3", "net eth0 x"), _ZONES)


def test_multiple_interfaces_populate_their_zones() -> None:
    result = parse_interfaces(_records("net eth0 detect", "loc eth1 detect"), _ZONES)
    by_name = {z.name: z for z in result.zones}
    assert by_name["net"].members == (ZoneMember(interface="eth0", family=Family.BOTH),)
    assert by_name["loc"].members == (ZoneMember(interface="eth1", family=Family.BOTH),)
    assert by_name["fw"].members == ()  # untouched


def test_parsed_zone_member_carries_source_location() -> None:
    # #316: located diagnostics — the parser stamps the row's path/line onto the member.
    result = parse_interfaces(_records("net eth0 detect"), _ZONES)
    net = next(z for z in result.zones if z.name == "net")
    (member,) = net.members
    assert (member.path, member.line) == ("interfaces", 1)


def test_zone_member_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = ZoneMember(interface="eth0", family=Family.BOTH, path="interfaces", line=1)
    b = ZoneMember(interface="eth0", family=Family.BOTH, path="other", line=9)
    assert a == b
