import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, SetDef, SetType
from shorewallnf.parser import Record, parse, parse_config, parse_sets
from shorewallnf.preprocessor import SourceLine, to_source_lines


def _records(*texts: str, path: str = "sets") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


# --- registry construction ---------------------------------------------------


def test_v4_and_v6_sets_produce_two_registry_entries() -> None:
    # A v4-typed set and a v6-typed set yield two entries with correct family/type.
    sets = parse_sets(_records("admins ipv4 address", "admins6 ipv6 address"))
    assert sets == {
        "admins": SetDef(
            name="admins", family=Family.IPV4, set_type=SetType.ADDRESS, path="sets", line=1
        ),
        "admins6": SetDef(
            name="admins6", family=Family.IPV6, set_type=SetType.ADDRESS, path="sets", line=2
        ),
    }


def test_both_family_and_address_port_type() -> None:
    (sdef,) = parse_sets(_records("services both address:port")).values()
    assert (sdef.family, sdef.set_type) == (Family.BOTH, SetType.ADDRESS_PORT)


def test_registry_is_keyed_by_name() -> None:
    sets = parse_sets(_records("a ipv4 address", "b ipv6 address:port"))
    assert set(sets) == {"a", "b"}
    assert sets["b"].set_type is SetType.ADDRESS_PORT


# --- fail-fast (ADR-0004, located errors) ------------------------------------


def test_unknown_set_type_fails_fast() -> None:
    with pytest.raises(ConfigError, match="unknown set type") as exc:
        parse_sets(_records("admins ipv4 network"))
    assert exc.value.line == 1
    assert exc.value.path == "sets"


def test_duplicate_set_name_fails_fast() -> None:
    with pytest.raises(ConfigError, match="duplicate set") as exc:
        parse_sets(_records("admins ipv4 address", "admins ipv6 address"))
    assert exc.value.line == 2


def test_missing_family_fails_fast() -> None:
    with pytest.raises(ConfigError, match="missing set family"):
        parse_sets(_records("admins"))


def test_unknown_family_token_fails_fast() -> None:
    with pytest.raises(ConfigError, match="unknown set family"):
        parse_sets(_records("admins ipv5 address"))


def test_missing_type_fails_fast() -> None:
    with pytest.raises(ConfigError, match="missing set type"):
        parse_sets(_records("admins ipv4"))


def test_empty_sets_file_yields_empty_registry() -> None:
    assert parse_sets(_records("# just a comment")) == {}


# --- parse_config wiring -----------------------------------------------------


def test_parse_config_carries_sets_into_the_ruleset() -> None:
    ruleset = parse_config(
        {"sets": to_source_lines("admins ipv4 address\nservices both address:port\n", "sets")}
    )
    assert ruleset.sets == {
        "admins": SetDef(
            name="admins", family=Family.IPV4, set_type=SetType.ADDRESS, path="sets", line=1
        ),
        "services": SetDef(
            name="services",
            family=Family.BOTH,
            set_type=SetType.ADDRESS_PORT,
            path="sets",
            line=2,
        ),
    }


def test_parse_config_without_sets_file_leaves_registry_empty() -> None:
    assert parse_config({}).sets == {}
