"""Validator stage tests (#138): dead ESTABLISHED/RELATED DROP/REJECT rules fail fast.

ADR-0005's base chains accept ``ct state {established, related}`` at the top of
``input``/``forward``. A rule in the ESTABLISHED or RELATED ``?SECTION`` is gated on that
same state but emitted *after* the base accept, so a ``DROP``/``REJECT`` there is
unreachable (dead). The Validator rejects it with an actionable, located-by-content error
(fail-closed). An ``ACCEPT`` there is a redundant no-op and is allowed; INVALID/NEW are
unaffected (their states are not in the base accept).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewallnf import cli
from shorewallnf.errors import ConfigError
from shorewallnf.ir import Family, Interface, Policy, Provider, Rule, Ruleset, Zone
from shorewallnf.validator import validate


def _rs(action: str, section: str | None) -> Ruleset:
    return Ruleset(
        zones=(Zone(name="net"), Zone(name="loc")),
        rules=(Rule(action=action, source="net", dest="loc", section=section),),
    )


# --- the shadowed sections reject DROP/REJECT --------------------------------


@pytest.mark.parametrize("section", ["ESTABLISHED", "RELATED"])
@pytest.mark.parametrize("action", ["DROP", "REJECT"])
def test_drop_or_reject_in_shadowed_section_fails_fast(action: str, section: str) -> None:
    with pytest.raises(ConfigError) as exc:
        validate(_rs(action, section))
    msg = str(exc.value)
    assert action in msg  # names the offending action
    assert section in msg  # names the section
    assert "ADR-0005" in msg  # names the base-accept shadow


def test_shadowed_section_error_cites_path_line() -> None:
    # #195: when the offending rule carries a source location, the error prefixes path:line.
    rule = Rule(action="DROP", source="net", dest="loc", section="ESTABLISHED",
                path="rules", line=12)
    with pytest.raises(ConfigError) as exc:
        validate(Ruleset(rules=(rule,)))
    assert str(exc.value).startswith("rules:12: ")


def test_message_is_actionable() -> None:
    msg = _message(_rs("DROP", "ESTABLISHED")).lower()
    assert "unreachable" in msg or "dead" in msg
    assert "base chain" in msg


def test_shadowed_section_check_is_case_insensitive() -> None:
    with pytest.raises(ConfigError):
        validate(_rs("DROP", "established"))


# --- allowed cases -----------------------------------------------------------


@pytest.mark.parametrize("section", ["ESTABLISHED", "RELATED"])
def test_accept_in_shadowed_section_is_a_noop(section: str) -> None:
    rs = _rs("ACCEPT", section)
    assert validate(rs) is rs  # allowed; returns the ruleset unchanged


@pytest.mark.parametrize("section", ["INVALID", "NEW", None])
@pytest.mark.parametrize("action", ["DROP", "REJECT"])
def test_drop_or_reject_outside_shadowed_sections_is_allowed(
    action: str, section: str | None
) -> None:
    rs = _rs(action, section)
    assert validate(rs) is rs  # INVALID/NEW/unsectioned are unaffected


def test_empty_ruleset_validates() -> None:
    rs = Ruleset()
    assert validate(rs) is rs


# --- wired into the compile pipeline -----------------------------------------


def _config(tmp_path: Path, rules: str) -> Path:
    (tmp_path / "zones").write_text("fw firewall\nnet ipv4\nloc ipv4\n")
    (tmp_path / "interfaces").write_text("net eth0 detect\nloc eth1 detect\n")
    (tmp_path / "policy").write_text("all all DROP\n")
    (tmp_path / "rules").write_text(rules)
    return tmp_path


def test_compile_rejects_drop_in_established_section(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "?SECTION ESTABLISHED\nDROP net loc\n")
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    assert "ESTABLISHED" in str(exc.value)


def test_compile_allows_accept_in_established_section(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "?SECTION ESTABLISHED\nACCEPT net loc\n")
    cli.compile_config(cfg)  # redundant no-op; must not raise


def test_compile_allows_drop_in_invalid_section(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "?SECTION INVALID\nDROP net loc\n")
    cli.compile_config(cfg)  # unaffected; must not raise


def test_compile_rejects_undeclared_zone_in_rules(tmp_path: Path) -> None:
    # #323: end-to-end, an undeclared zone in `rules` is rejected by the Validator (the parser is
    # now purely syntactic), with a located message naming the unknown zone.
    cfg = _config(tmp_path, "ACCEPT wan loc\n")
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    msg = str(exc.value)
    assert msg.startswith("rules:") and "wan" in msg


def test_compile_rejects_undeclared_zone_in_policy(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "")
    (cfg / "policy").write_text("net wan DROP\n")
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    msg = str(exc.value)
    assert msg.startswith("policy:") and "wan" in msg


def _message(rs: Ruleset) -> str:
    with pytest.raises(ConfigError) as exc:
        validate(rs)
    return str(exc.value)


# --- provider definitions: duplicate mark / table id / unknown interface (#233) ---

_ETH = (Interface(name="eth0"), Interface(name="eth1"))


def _providers_rs(*providers: Provider) -> Ruleset:
    return Ruleset(providers=providers, interfaces=_ETH)


def test_valid_provider_set_passes_unchanged() -> None:
    rs = _providers_rs(
        Provider(name="wan1", number=1, mark=1, interface="eth0", gateway="192.0.2.1"),
        Provider(name="wan2", number=2, mark=2, interface="eth1", gateway="198.51.100.1"),
    )
    assert validate(rs) is rs  # pure IR -> IR, no mutation


def test_duplicate_fwmark_fails_fast() -> None:
    msg = _message(
        _providers_rs(
            Provider(name="wan1", number=1, mark=1, interface="eth0", gateway="192.0.2.1"),
            Provider(name="wan2", number=2, mark=1, interface="eth1", gateway="198.51.100.1"),
        )
    )
    assert "fwmark" in msg and "wan1" in msg and "wan2" in msg  # names the collision


def test_duplicate_provider_number_fails_fast() -> None:
    msg = _message(
        _providers_rs(
            Provider(name="wan1", number=1, mark=1, interface="eth0", gateway="192.0.2.1"),
            Provider(name="wan2", number=1, mark=2, interface="eth1", gateway="198.51.100.1"),
        )
    )
    assert "wan1" in msg and "wan2" in msg and "1" in msg  # names both and the shared table id


def test_unknown_interface_fails_fast() -> None:
    msg = _message(
        _providers_rs(
            Provider(name="wan1", number=1, mark=1, interface="eth9", gateway="192.0.2.1"),
        )
    )
    assert "wan1" in msg and "eth9" in msg  # names the provider and the unknown interface


def test_provider_validation_error_cites_source_location() -> None:
    # #251: a Provider carrying path/line yields a located ConfigError (mirrors Rule, #198/#195).
    rs = Ruleset(
        providers=(
            Provider(name="wan1", number=1, mark=1, interface="eth0",
                     gateway="192.0.2.1", path="providers", line=3),
            Provider(name="wan2", number=2, mark=1, interface="eth1",
                     gateway="198.51.100.1", path="providers", line=4),
        ),
        interfaces=_ETH,
    )
    # The collision fires on the second (line 4) provider, so the error prefixes providers:4.
    assert str(_message(rs)).startswith("providers:4: ")


# --- reserved routing-table numbers + fwmark 0 (#255) ------------------------


@pytest.mark.parametrize("number", [0, 253, 254, 255])
def test_reserved_routing_table_number_fails_fast(number: int) -> None:
    # 0/253/254/255 are the kernel's unspec/default/main/local tables — assigning one lets
    # teardown `ip route flush` a system table (destructive).
    rs = _providers_rs(
        Provider(name="wan", number=number, mark=1, interface="eth0", gateway="192.0.2.1"),
    )
    with pytest.raises(ConfigError, match="reserved"):
        validate(rs)


def test_out_of_range_routing_table_number_fails_fast() -> None:
    rs = _providers_rs(
        Provider(name="wan", number=2**32, mark=1, interface="eth0", gateway="192.0.2.1"),
    )
    with pytest.raises(ConfigError, match="number"):
        validate(rs)


def test_fwmark_zero_fails_fast() -> None:
    # fwmark 0 matches *unmarked* traffic, silently routing everything out this provider.
    rs = _providers_rs(
        Provider(name="wan", number=1, mark=0, interface="eth0", gateway="192.0.2.1"),
    )
    with pytest.raises(ConfigError, match="fwmark"):
        validate(rs)


def test_out_of_range_fwmark_fails_fast() -> None:
    rs = _providers_rs(
        Provider(name="wan", number=1, mark=2**32, interface="eth0", gateway="192.0.2.1"),
    )
    with pytest.raises(ConfigError, match="fwmark"):
        validate(rs)


def test_valid_boundary_number_and_mark_pass() -> None:
    # 0xFFFFFFFF is reserved for tproxy (ADR-0051), so the largest valid provider values are
    # now 0xFFFFFFFE for both number and mark; a non-reserved id passes unchanged.
    rs = _providers_rs(
        Provider(name="wan", number=0xFFFFFFFE, mark=0xFFFFFFFE, interface="eth0",
                 gateway="192.0.2.1"),
    )
    assert validate(rs) is rs


# --- 0xFFFFFFFF reserved for the transparent-proxy mark/table (ADR-0051, #290) -----------


def test_reserved_tproxy_fwmark_fails_fast() -> None:
    # 0xFFFFFFFF == TPROXY_MARK; a provider claiming it would let a tproxy'd packet select the
    # provider table instead of the local-delivery table (silent misroute).
    rs = _providers_rs(
        Provider(name="wan", number=1, mark=0xFFFFFFFF, interface="eth0", gateway="192.0.2.1"),
    )
    with pytest.raises(ConfigError, match="fwmark") as exc:
        validate(rs)
    assert "0xffffffff" in str(exc.value).lower() and "tproxy" in str(exc.value).lower()


def test_reserved_tproxy_table_id_fails_fast() -> None:
    # 0xFFFFFFFF == TPROXY_TABLE_ID; reserved for tproxy local delivery alongside the kernel ids.
    rs = _providers_rs(
        Provider(name="wan", number=0xFFFFFFFF, mark=1, interface="eth0", gateway="192.0.2.1"),
    )
    with pytest.raises(ConfigError, match="number") as exc:
        validate(rs)
    assert "0xffffffff" in str(exc.value).lower() and "tproxy" in str(exc.value).lower()


# --- malformed proto/port combinations in rules (#317) -----------------------


def _rule_rs(**kw: object) -> Ruleset:
    base: dict[str, object] = {"action": "ACCEPT", "source": "net", "dest": "loc"}
    base.update(kw)
    # Declare the referenced zones so zone-reference validation (#323) doesn't fire first —
    # these cases exercise proto/port checks, not undeclared-zone rejection.
    return Ruleset(
        zones=(Zone(name="net"), Zone(name="loc")),
        rules=(Rule(**base),),  # type: ignore[arg-type]
    )


def test_dport_without_proto_fails_fast() -> None:
    msg = _message(_rule_rs(dport="80"))
    assert "80" in msg  # names the offending port
    assert "proto" in msg.lower()  # points at the missing protocol column


def test_sport_without_proto_fails_fast() -> None:
    msg = _message(_rule_rs(sport="1024"))
    assert "1024" in msg
    assert "proto" in msg.lower()


def test_portless_proto_only_rule_is_allowed() -> None:
    rs = _rule_rs(proto="tcp")  # a bare proto with no port is fine
    assert validate(rs) is rs


def test_tcp_with_ports_is_allowed() -> None:
    rs = _rule_rs(proto="tcp", dport="80", sport="1024")
    assert validate(rs) is rs


def test_port_without_proto_cites_path_line() -> None:
    rule = Rule(action="ACCEPT", source="net", dest="loc", dport="80",
                path="rules", line=7)
    with pytest.raises(ConfigError) as exc:
        validate(Ruleset(rules=(rule,)))
    assert str(exc.value).startswith("rules:7: ")


@pytest.mark.parametrize("proto", ["icmp", "ipv6-icmp"])
def test_icmp_with_source_port_fails_fast(proto: str) -> None:
    fam = Family.IPV4 if proto == "icmp" else Family.IPV6
    msg = _message(_rule_rs(proto=proto, sport="80", family=fam))
    assert proto in msg  # names the port-less protocol
    assert "source port" in msg.lower() or "sport" in msg.lower()


@pytest.mark.parametrize("proto", ["icmp", "ipv6-icmp"])
def test_icmp_with_dest_port_type_is_allowed(proto: str) -> None:
    # For ICMP the DEST PORT column carries the ICMP *type*, not a port (ADR-0007) — allowed.
    fam = Family.IPV4 if proto == "icmp" else Family.IPV6
    rs = _rule_rs(proto=proto, dport="8", family=fam)
    assert validate(rs) is rs


def test_icmp_source_port_error_cites_path_line() -> None:
    rule = Rule(action="ACCEPT", source="net", dest="loc", proto="icmp",
                sport="80", family=Family.IPV4, path="rules", line=9)
    with pytest.raises(ConfigError) as exc:
        validate(Ruleset(rules=(rule,)))
    assert str(exc.value).startswith("rules:9: ")


def test_compile_rejects_port_without_proto(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "ACCEPT net loc - 80\n")  # dest-port, empty proto column
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    assert "80" in str(exc.value)


def test_compile_rejects_icmp_source_port(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "ACCEPT net loc icmp - 80\n")  # sport on icmp
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    assert "icmp" in str(exc.value)


# --- zone reference integrity in policy and rules (#323, epic #312) -----------
#
# Every zone named in `policy`/`rules`/`stoppedrules` must be declared in `zones` (the firewall
# zone included) or be the `all` wildcard; the zone part of a `zone:host` token is resolved the
# same way. An undeclared reference fails fast with a located ConfigError (ADR-0004). This is the
# validator's job (cross-file reference integrity), mirroring the provider/interface check above.

_ZONES = (
    Zone(name="net"),
    Zone(name="loc"),
    Zone(name="fw", is_firewall=True),
)


def _zone_rs(*, policies: tuple[Policy, ...] = (), rules: tuple[Rule, ...] = (),
            stopped_rules: tuple[Rule, ...] = ()) -> Ruleset:
    return Ruleset(zones=_ZONES, policies=policies, rules=rules, stopped_rules=stopped_rules)


def test_policy_undeclared_source_zone_fails_with_location() -> None:
    rs = _zone_rs(policies=(
        Policy(source="wan", dest="loc", action="DROP", path="policy", line=4),
    ))
    msg = str(_message(rs))
    assert msg.startswith("policy:4: ")  # located
    assert "wan" in msg  # names the unknown zone


def test_policy_undeclared_dest_zone_fails_with_location() -> None:
    rs = _zone_rs(policies=(
        Policy(source="net", dest="dmz", action="DROP", path="policy", line=7),
    ))
    msg = str(_message(rs))
    assert msg.startswith("policy:7: ") and "dmz" in msg


def test_rule_undeclared_source_zone_fails_with_location() -> None:
    rs = _zone_rs(rules=(
        Rule(action="ACCEPT", source="wan", dest="loc", path="rules", line=3),
    ))
    msg = str(_message(rs))
    assert msg.startswith("rules:3: ") and "wan" in msg


def test_rule_undeclared_dest_zone_fails_with_location() -> None:
    rs = _zone_rs(rules=(
        Rule(action="ACCEPT", source="net", dest="dmz", path="rules", line=9),
    ))
    msg = str(_message(rs))
    assert msg.startswith("rules:9: ") and "dmz" in msg


def test_rule_zone_host_undeclared_zone_part_fails() -> None:
    # The zone part of a `zone:host` token is resolved; `wan:192.0.2.5` names undeclared `wan`.
    rs = _zone_rs(rules=(
        Rule(action="ACCEPT", source="wan:192.0.2.5", dest="loc", path="rules", line=2),
    ))
    msg = str(_message(rs))
    assert msg.startswith("rules:2: ") and "wan" in msg
    assert "192.0.2.5" not in msg  # only the zone part is reported, not the host


def test_stopped_rule_undeclared_zone_fails_with_location() -> None:
    rs = _zone_rs(stopped_rules=(
        Rule(action="ACCEPT", source="wan", dest="fw", path="stoppedrules", line=1),
    ))
    msg = str(_message(rs))
    assert msg.startswith("stoppedrules:1: ") and "wan" in msg


def test_firewall_zone_resolves_no_false_positive() -> None:
    # The firewall zone (is_firewall) is declared like any other; referencing it must not raise.
    rs = _zone_rs(
        policies=(Policy(source="fw", dest="net", action="ACCEPT"),),
        rules=(Rule(action="ACCEPT", source="fw", dest="loc"),),
    )
    assert validate(rs) is rs


def test_all_wildcard_resolves() -> None:
    rs = _zone_rs(
        policies=(Policy(source="all", dest="all", action="DROP"),),
        rules=(Rule(action="ACCEPT", source="all", dest="net"),),
    )
    assert validate(rs) is rs


def test_valid_zone_references_pass_unchanged() -> None:
    rs = _zone_rs(
        policies=(Policy(source="net", dest="loc", action="DROP"),),
        rules=(Rule(action="ACCEPT", source="loc:192.0.2.0/24", dest="net"),),
        stopped_rules=(Rule(action="ACCEPT", source="net", dest="fw"),),
    )
    assert validate(rs) is rs


# --- duplicate / contradictory policies (#326, epic #312) --------------------
#
# A `policy` file may hold only one entry per (source, dest) pair: a second entry is dead
# (never reached), and a second with a *different* action is a silent footgun. Both fail fast
# with one located ConfigError naming both entries' file:line (ADR-0004). Distinct pairs —
# including `all`/wildcard rows — are unaffected.


def test_contradictory_policies_fail_with_both_locations() -> None:
    rs = _zone_rs(policies=(
        Policy(source="net", dest="loc", action="ACCEPT", path="policy", line=3),
        Policy(source="net", dest="loc", action="DROP", path="policy", line=8),
    ))
    msg = str(_message(rs))
    assert msg.startswith("policy:8: ")  # located at the second (offending) entry
    assert "policy:3" in msg  # cites the first entry's location too
    assert "ACCEPT" in msg and "DROP" in msg  # names both conflicting actions


def test_exact_duplicate_policy_fails_with_both_locations() -> None:
    rs = _zone_rs(policies=(
        Policy(source="net", dest="loc", action="DROP", path="policy", line=2),
        Policy(source="net", dest="loc", action="DROP", path="policy", line=5),
    ))
    msg = str(_message(rs))
    assert msg.startswith("policy:5: ")  # located at the second (dead) entry
    assert "policy:2" in msg  # cites the first entry's location too
    assert "duplicate" in msg.lower()


def test_distinct_policy_pairs_pass_unchanged() -> None:
    rs = _zone_rs(policies=(
        Policy(source="net", dest="loc", action="DROP"),
        Policy(source="loc", dest="net", action="ACCEPT"),
        Policy(source="all", dest="all", action="REJECT"),  # wildcard row is its own pair
    ))
    assert validate(rs) is rs


def test_swapped_source_dest_is_a_distinct_pair() -> None:
    # (net, loc) and (loc, net) are different directions, not a duplicate.
    rs = _zone_rs(policies=(
        Policy(source="net", dest="loc", action="ACCEPT"),
        Policy(source="loc", dest="net", action="DROP"),
    ))
    assert validate(rs) is rs


def test_compile_rejects_contradictory_policy(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "")
    (cfg / "policy").write_text("net loc ACCEPT\nnet loc DROP\n")
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    msg = str(exc.value)
    assert "ACCEPT" in msg and "DROP" in msg


def test_compile_rejects_duplicate_policy(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "")
    (cfg / "policy").write_text("net loc DROP\nnet loc DROP\n")
    with pytest.raises(ConfigError) as exc:
        cli.compile_config(cfg)
    assert "duplicate" in str(exc.value).lower()
