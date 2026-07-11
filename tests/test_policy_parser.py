import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.ir import Policy, RateLimit
from shorewallnf.parser import Record, parse, parse_policies
from shorewallnf.preprocessor import SourceLine

# Zone-reference integrity (undeclared zone names) is enforced by the Validator, not the parser
# (#323); parse_policies is purely syntactic, so these tests need no declared-zone fixture.


def _records(*texts: str, path: str = "policy") -> list[Record]:
    lines = [SourceLine(text=t, path=path, line=i) for i, t in enumerate(texts, 1)]
    return parse(lines)


def test_basic_policy() -> None:
    (policy,) = parse_policies(_records("loc net ACCEPT"))
    assert policy == Policy(source="loc", dest="net", action="ACCEPT")


def test_policy_with_log_level() -> None:
    (policy,) = parse_policies(_records("dmz loc REJECT info"))
    assert policy == Policy(source="dmz", dest="loc", action="REJECT", log_level="info")


def test_all_wildcard_source_and_dest() -> None:
    (policy,) = parse_policies(_records("all all REJECT info"))
    assert (policy.source, policy.dest) == ("all", "all")


def test_firewall_zone_accepted() -> None:
    (policy,) = parse_policies(_records("fw net ACCEPT"))
    assert policy.source == "fw"


def test_representative_policy_file() -> None:
    records = _records(
        "loc net ACCEPT", "fw net ACCEPT", "net all DROP info", "all all REJECT info"
    )
    assert [
        (p.source, p.dest, p.action, p.log_level) for p in parse_policies(records)
    ] == [
        ("loc", "net", "ACCEPT", None),
        ("fw", "net", "ACCEPT", None),
        ("net", "all", "DROP", "info"),
        ("all", "all", "REJECT", "info"),
    ]


def test_unknown_action_raises_with_location() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net ACCEPT", "loc dmz BOGUS"))
    assert exc.value.line == 2
    assert "BOGUS" in str(exc.value)


def test_missing_action_raises() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net"))
    assert "action" in str(exc.value)


def test_unsupported_trailing_columns_rejected() -> None:
    # LIMIT:BURST (column 4) is supported; CONNLIMIT (column 5) is not yet (#407) — rather than
    # silently drop it, reject until supported (#94, fail-fast).
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("net all DROP info 10/sec:20 4"))
    assert exc.value.line == 1


def test_four_columns_still_accepted() -> None:
    (policy,) = parse_policies(_records("net all DROP info"))
    assert policy.log_level == "info"


# --- LIMIT:BURST rate column (#408) ------------------------------------------


def test_policy_rate_with_burst() -> None:
    # Column 4 (after the `-` log-level placeholder) parses via the shared helper (#406).
    (policy,) = parse_policies(_records("net all DROP - 10/min:20"))
    assert policy.rate == RateLimit(10, "minute", 20)


def test_policy_rate_without_burst_with_log_level() -> None:
    (policy,) = parse_policies(_records("net all DROP info 10/min"))
    assert policy.log_level == "info"
    assert policy.rate == RateLimit(10, "minute", None)


def test_policy_absent_rate_column_is_none() -> None:
    (policy,) = parse_policies(_records("net all DROP"))
    assert policy.rate is None


def test_policy_dash_rate_column_is_none() -> None:
    # An explicit `-` in the LIMIT column is the "unspecified" placeholder, not a rate.
    (policy,) = parse_policies(_records("net all DROP - -"))
    assert policy.rate is None


@pytest.mark.parametrize(
    "spec", ["10/fortnight", "abc", "10/min:xyz"]
)
def test_policy_malformed_rate_fails_fast(spec: str) -> None:
    with pytest.raises(ConfigError, match="rate limit"):
        parse_policies(_records(f"net all DROP - {spec}"))


def test_policy_malformed_rate_error_is_located() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net ACCEPT", "net all DROP - 10/fortnight"))
    assert exc.value.line == 2


# --- log-level validation (#117) ---------------------------------------------


@pytest.mark.parametrize(
    "level", ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug", "audit"]
)
def test_valid_nft_log_levels_accepted(level: str) -> None:
    (policy,) = parse_policies(_records(f"net all DROP {level}"))
    assert policy.log_level == level


@pytest.mark.parametrize(
    "bad",
    ["warning", "error", "panic", "6", "NFLOG", "ULOG", "Info"],
)
def test_unsupported_log_level_fails_fast(bad: str) -> None:
    # syslog spellings, numeric levels, NFLOG/ULOG targets, and non-lowercase spellings
    # aren't nft `log level` values — reject rather than emit an invalid ruleset (ADR-0004).
    with pytest.raises(ConfigError, match="log level"):
        parse_policies(_records(f"net all DROP {bad}"))


def test_unsupported_log_level_error_is_located() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_policies(_records("loc net ACCEPT", "net all DROP warning"))
    assert exc.value.line == 2


def test_parsed_policy_carries_source_location() -> None:
    # #316: located diagnostics — the parser stamps the row's path/line onto the IR.
    (policy,) = parse_policies(_records("loc net ACCEPT"))
    assert (policy.path, policy.line) == ("policy", 1)


def test_policy_location_is_not_part_of_equality() -> None:
    # path/line are compare=False metadata (ADR-0001), mirroring Rule (#195).
    a = Policy(source="loc", dest="net", action="ACCEPT", path="policy", line=1)
    b = Policy(source="loc", dest="net", action="ACCEPT", path="other", line=9)
    assert a == b
