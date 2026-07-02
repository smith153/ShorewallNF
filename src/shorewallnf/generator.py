"""Generator — the pure IR → nftables JSON stage (ADR-0001/0003).

Consumes the family-aware IR and emits the base ``inet`` skeleton (ADR-0005), then the
per-connection feature rules from the ``Rule`` IR (ADR-0007), then the inter-zone
default-policy rules from the ``Policy`` IR (ADR-0006), as ``python3-nftables`` JSON: one
``inet filter`` table, the fail-closed ``input``/``forward``/``output`` base chains, the
always-on stateful + loopback accepts, the feature rules, and finally one rule per policy.
Feature rules land in their chain **before** the policy fall-through, so an explicit verdict
wins over the zone-pair default. It is dual-stack by construction (ADR-0002) and
golden-file-testable without an ``nft`` binary.
"""

from __future__ import annotations

from typing import Any

from .errors import ConfigError
from .ir import Family, Nat, Policy, Rule, Ruleset, Zone

_FAMILY = "inet"
_TABLE = "filter"
_NAT_TABLE = "nat"

# (chain name == hook name, base-chain policy). Input/forward fail closed; output accepts.
_BASE_CHAINS = (("input", "drop"), ("forward", "drop"), ("output", "accept"))

# nft verdict keyword per (uppercase) policy action; the parser guarantees these three.
_VERDICTS = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject"}

_Command = dict[str, Any]


def generate(ruleset: Ruleset) -> dict[str, list[_Command]]:
    """Emit base skeleton (ADR-0005), then feature rules (ADR-0007), then policies (ADR-0006)."""
    commands: list[_Command] = [_table()]
    commands += [_chain(name, policy) for name, policy in _BASE_CHAINS]
    commands.append(_rule("input", [_ct_established_related(), _accept()]))
    commands.append(_rule("input", [_ifname("iifname", "lo"), _accept()]))
    commands.append(_rule("forward", [_ct_established_related(), _accept()]))
    commands += _nat_base(ruleset)
    commands += _feature_rules(ruleset)
    commands += _nat_rules(ruleset)
    commands += _policy_rules(ruleset)
    return {"nftables": commands}


# ---- inter-zone default-policy rules (ADR-0006) -----------------------------------------


def _policy_rules(ruleset: Ruleset) -> list[_Command]:
    """One nft rule per policy, ordered specific-pair → single-``all`` → ``all all`` last."""
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = {zone.name for zone in ruleset.zones if zone.is_firewall}
    ordered = sorted(ruleset.policies, key=_specificity)
    return [_policy_rule(policy, interfaces, firewalls) for policy in ordered]


def _zone_interfaces(zones: tuple[Zone, ...]) -> dict[str, tuple[str, ...]]:
    """Map each zone to its (deduplicated, order-preserving) interface names."""
    return {zone.name: tuple(dict.fromkeys(m.interface for m in zone.members)) for zone in zones}


def _specificity(policy: Policy) -> int:
    """Sort key: 0 = specific zone pair, 1 = one ``all`` side, 2 = ``all all`` (emitted last)."""
    return (policy.source == "all") + (policy.dest == "all")


def _policy_rule(
    policy: Policy, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> _Command:
    ctx = f"policy {policy.source!r} {policy.dest!r}"
    chain, expr = _chain_and_zone_matches(
        policy.source, policy.dest, interfaces, firewalls, ctx
    )
    if policy.log_level:
        expr.append(_log(policy.log_level))
    expr.append(_verdict(policy.action))
    return _rule(chain, expr)


def _chain_and_zone_matches(
    source: str,
    dest: str,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    ctx: str,
) -> tuple[str, list[_Command]]:
    """Base chain (by the role of ``$FW``) and the per-side interface matches.

    The ADR-0006 zone-matching structure, shared by policy defaults and feature rules (ADR-0007):
    ``$FW`` as source is host ``output``, as dest host ``input``, otherwise ``forward``; each
    non-``all``, non-``$FW`` side matches its zone's interface(s).
    """
    src_fw = source in firewalls
    dst_fw = dest in firewalls
    chain = "output" if src_fw else "input" if dst_fw else "forward"
    expr: list[_Command] = []
    if chain in ("forward", "input") and source != "all" and not src_fw:
        expr.append(_ifname("iifname", _iface_value(ctx, source, interfaces)))
    if chain in ("forward", "output") and dest != "all" and not dst_fw:
        expr.append(_ifname("oifname", _iface_value(ctx, dest, interfaces)))
    return chain, expr


def _iface_value(
    ctx: str, zone: str, interfaces: dict[str, tuple[str, ...]]
) -> str | dict[str, Any]:
    """A single interface name, or an anonymous set when the zone spans several."""
    names = interfaces.get(zone, ())
    if not names:
        raise ConfigError(f"{ctx}: zone {zone!r} has no interfaces to match on")
    return names[0] if len(names) == 1 else {"set": list(names)}


# ---- per-connection feature rules (ADR-0007) --------------------------------------------


def _feature_rules(ruleset: Ruleset) -> list[_Command]:
    """One nft rule per ``Rule``, ordered by ``?SECTION`` then file order, before the defaults.

    Rules are grouped by connection-state section (ADR-0007): the state-gated
    ESTABLISHED → RELATED → INVALID fast-path first, then the ungated NEW rules, stably within
    each. Sorting before the policy fall-through keeps explicit verdicts ahead of the defaults.
    """
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = {zone.name for zone in ruleset.zones if zone.is_firewall}
    ordered = sorted(ruleset.rules, key=lambda rule: _SECTION_ORDER[_section_of(rule)])
    return [cmd for rule in ordered for cmd in _feature_rule(rule, interfaces, firewalls)]


def _feature_rule(
    rule: Rule, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> list[_Command]:
    """The nft rule(s) for one ``Rule``; a both-family ICMP rule splits into one per family."""
    ctx = f"rule {rule.action} {rule.source!r} {rule.dest!r}"
    chain, prefix = _chain_and_zone_matches(
        _zone_of(rule.source), _zone_of(rule.dest), interfaces, firewalls, ctx
    )
    prefix += _host_matches(rule)
    prefix += _ct_matches(rule)
    verdict = _verdict(rule.action)
    if rule.proto in _ICMP_PROTOS:
        return [_rule(chain, [*prefix, match, verdict]) for match in _icmp_matches(rule, ctx)]
    return [_rule(chain, [*prefix, *_l4_matches(rule, ctx), verdict])]


# ?SECTION connection-state gating & ordering (ADR-0007). ESTABLISHED/RELATED/INVALID gate on
# ``ct state`` and form the fast-path; NEW (the default for an unsectioned rule) is ungated —
# the ADR-0005 base rules already fast-path established/related, so NEW rules only see new packets.
_SECTION_ORDER = {"ESTABLISHED": 0, "RELATED": 1, "INVALID": 2, "NEW": 3}
_SECTION_STATE = {"ESTABLISHED": "established", "RELATED": "related", "INVALID": "invalid"}


def _section_of(rule: Rule) -> str:
    """The rule's section upper-cased; unsectioned defaults to ``NEW`` (fail fast otherwise)."""
    section = (rule.section or "NEW").upper()
    if section not in _SECTION_ORDER:
        raise ConfigError(
            f"rule {rule.action} {rule.source!r} {rule.dest!r}: unsupported ?SECTION "
            f"{rule.section!r} (ESTABLISHED/RELATED/INVALID/NEW)"
        )
    return section


def _ct_matches(rule: Rule) -> list[_Command]:
    """A ``ct state`` match for a state-gated section; NEW rules add none."""
    state = _SECTION_STATE.get(_section_of(rule))
    return [_ct_state(state)] if state is not None else []


def _ct_state(state: str) -> _Command:
    return {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": state}}


# ICMP is family-correct: ``icmp`` (IPv4) / ``ipv6-icmp`` (IPv6) as the l4proto, ``icmp``/``icmpv6``
# as the payload protocol for a type match. The match itself is the family guard (ADR-0007), so a
# both-family rule splits into one rule per family (ADR-0002) rather than adding a meta nfproto.
_ICMP_PROTOS = ("icmp", "ipv6-icmp")


def _icmp_matches(rule: Rule, ctx: str) -> list[_Command]:
    """One ICMP match per family the rule scopes to.

    ICMP has no source port; the DEST PORT column carries an optional ICMP type. A both-family
    rule yields a v4 ``icmp`` and a v6 ``icmpv6`` match; a family-pinned rule yields only its own.
    """
    if rule.sport is not None:
        raise ConfigError(f"{ctx}: an ICMP rule has no source port")
    v6_flags: tuple[bool, ...] = (
        (False, True) if rule.family is Family.BOTH else (rule.family is Family.IPV6,)
    )
    return [_icmp_match(v6, rule.dport) for v6 in v6_flags]


def _icmp_match(v6: bool, icmp_type: str | None) -> _Command:
    if icmp_type is None:
        return _l4proto("ipv6-icmp" if v6 else "icmp")
    left = {"payload": {"protocol": "icmpv6" if v6 else "icmp", "field": "type"}}
    return {"match": {"op": "==", "left": left, "right": _port_value(icmp_type)}}


def _zone_of(token: str) -> str:
    """The zone part of a ``zone`` or ``zone:host`` token (task #123 narrows on the host)."""
    return token.split(":", 1)[0]


def _host_of(token: str) -> str | None:
    """The host/CIDR part of a ``zone:host`` token, or ``None`` for a bare zone."""
    _, sep, host = token.partition(":")
    return host if sep else None


def _host_matches(rule: Rule) -> list[_Command]:
    """``ip``/``ip6`` ``saddr``/``daddr`` narrowing from a ``zone:host`` source/dest (ADR-0007).

    Family comes from the literal (``:`` marks IPv6, ADR-0002); the family-specific match is the
    family guard, so no ``meta nfproto`` is added. Emitted after the interface matches and before
    the L4 matches; source narrows on ``saddr``, dest on ``daddr``.
    """
    matches: list[_Command] = []
    src_host = _host_of(rule.source)
    if src_host is not None:
        matches.append(_addr_match("saddr", src_host))
    dst_host = _host_of(rule.dest)
    if dst_host is not None:
        matches.append(_addr_match("daddr", dst_host))
    return matches


def _addr_match(field: str, host: str) -> _Command:
    proto = "ip6" if ":" in host else "ip"
    left = {"payload": {"protocol": proto, "field": field}}
    return {"match": {"op": "==", "left": left, "right": _addr_value(host)}}


def _addr_value(host: str) -> str | dict[str, Any]:
    """A bare address (scalar) or a CIDR literal as an nft ``prefix``."""
    if "/" in host:
        addr, length = host.rsplit("/", 1)
        return {"prefix": {"addr": addr, "len": int(length)}}
    return host


def _l4_matches(rule: Rule, ctx: str) -> list[_Command]:
    """tcp/udp protocol & port matches (ADR-0007).

    A proto-only rule matches ``meta l4proto``; with ports we emit a payload match per column
    (``dport`` before ``sport``) — nft folds the protocol dependency back in on load, so the
    bare payload match is the canonical form. A port without a protocol fails fast (ADR-0004).
    """
    if rule.proto is None:
        if rule.dport is not None or rule.sport is not None:
            raise ConfigError(f"{ctx}: a port match needs a protocol")
        return []
    if rule.dport is None and rule.sport is None:
        return [_l4proto(rule.proto)]
    matches: list[_Command] = []
    if rule.dport is not None:
        matches.append(_port_match(rule.proto, "dport", rule.dport))
    if rule.sport is not None:
        matches.append(_port_match(rule.proto, "sport", rule.sport))
    return matches


def _l4proto(proto: str) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": proto}}


def _port_match(proto: str, field: str, spec: str) -> _Command:
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": proto, "field": field}},
            "right": _port_value(spec),
        }
    }


def _port_value(spec: str) -> int | str | dict[str, Any]:
    """A single port (scalar), a comma-list (anonymous set), or an ``a:b`` range."""
    elems = [_port_elem(elem) for elem in spec.split(",")]
    return elems[0] if len(elems) == 1 else {"set": elems}


def _port_elem(elem: str) -> int | str | dict[str, Any]:
    if ":" in elem:
        low, high = elem.split(":", 1)
        return {"range": [_port(low), _port(high)]}
    return _port(elem)


def _port(token: str) -> int | str:
    """A numeric port as ``int`` (nft's canonical form); a service name passes through verbatim."""
    token = token.strip()
    return int(token) if token.isdigit() else token


def _log(level: str) -> _Command:
    return {"log": {"level": level}}


def _verdict(action: str) -> _Command:
    return {_VERDICTS[action]: None}


# ---- IPv4 DNAT: nat prerouting + forward accept (ADR-0008) -------------------------------

# nftables standard NAT hook priorities: dstnat for prerouting, srcnat for postrouting.
_DSTNAT_PRIO = -100
_SRCNAT_PRIO = 100


def _needs_nat_table(nat: Nat) -> bool:
    """True for a NAT entry compiled into the ``inet nat`` table.

    Every NAT kind uses it **except** an IPv6 DNAT, which does no NAT (ADR-0002) and compiles to a
    direct forward ``ACCEPT`` (#144) — no nat table / prerouting.
    """
    return nat.family is not Family.IPV6


def _nat_base(ruleset: Ruleset) -> list[_Command]:
    """The nat skeleton — ``inet nat`` table + prerouting/postrouting chains — if NAT is used.

    Unlike the always-present ADR-0005 filter skeleton, the nat plumbing is emitted only when a
    NAT entry actually needs the nat table (ADR-0008); a config whose only NAT entries are IPv6
    DNATs (direct-accept, no NAT) carries no nat table, as does one with no NAT at all.
    ``postrouting`` is part of the fixed pair even for a DNAT-only config, ready for the
    SNAT/MASQUERADE sibling.
    """
    if not any(_needs_nat_table(nat) for nat in ruleset.nats):
        return []
    return [
        _nat_table(),
        _nat_chain("prerouting", _DSTNAT_PRIO),
        _nat_chain("postrouting", _SRCNAT_PRIO),
    ]


def _nat_rules(ruleset: Ruleset) -> list[_Command]:
    """Per DNAT, a nat ``prerouting`` dnat rule and the matching filter ``forward`` accept."""
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = {zone.name for zone in ruleset.zones if zone.is_firewall}
    return [cmd for nat in ruleset.nats for cmd in _dnat(nat, interfaces, firewalls)]


def _dnat(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> list[_Command]:
    """Compile one ``DNAT`` by family: v4 NAT (ADR-0008) or v6 direct-accept (ADR-0002, #144)."""
    ctx = f"DNAT {nat.source!r} {nat.dest!r}"
    if nat.action != "DNAT":
        raise ConfigError(
            f"{ctx}: unsupported NAT {nat.action} — only DNAT is compiled here "
            "(SNAT/MASQUERADE #76)"
        )
    if nat.family is Family.IPV4:
        return _dnat_v4(nat, interfaces, firewalls, ctx)
    if nat.family is Family.IPV6:
        return [_dnat_v6_accept(nat, interfaces, firewalls, ctx)]
    raise ConfigError(f"{ctx}: a DNAT must scope to IPv4 or IPv6, not {nat.family.value}")


def _dnat_v4(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str], ctx: str
) -> list[_Command]:
    """The nat prerouting dnat rule + filter forward accept for one v4 ``DNAT`` (ADR-0008)."""
    host, _, remap = (nat.to or "").partition(":")
    if not host:
        raise ConfigError(f"{ctx}: DNAT target has no host")
    remap_port = remap or None
    return [
        _prerouting_rule(nat, host, remap_port, interfaces, firewalls, ctx),
        _forward_accept(nat, host, remap_port, interfaces, firewalls, ctx),
    ]


def _dnat_v6_accept(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str], ctx: str
) -> _Command:
    """IPv6 service exposure: a plain forward ``ACCEPT`` to the v6 address, no NAT (ADR-0002).

    IPv6 does no NAT, so there is no prerouting rewrite and no nat table (#144): the connection
    already carries its final destination, and we simply admit it through the fail-closed forward
    chain. Reuses the ADR-0006/0007 zone matching; the ``ip6 daddr`` match is the family guard, and
    proto/dest-port match as for a normal v6 rule (ADR-0007). Emitted before the policy defaults
    (as the v4 forward accept is) so the fall-through cannot shadow it.
    """
    if not nat.to:
        raise ConfigError(f"{ctx}: DNAT target has no host")
    chain, expr = _chain_and_zone_matches(nat.source, nat.dest, interfaces, firewalls, ctx)
    expr.append(_addr_match("daddr", nat.to))
    expr += _nat_l4_matches(nat.proto, nat.dport, ctx)
    expr.append(_accept())
    return _rule(chain, expr)


def _prerouting_rule(
    nat: Nat,
    host: str,
    remap_port: str | None,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    ctx: str,
) -> _Command:
    """``iifname <source> <proto> dport <ext-port> dnat to <host>[:<remap>]`` in nat prerouting."""
    expr: list[_Command] = []
    if nat.source != "all" and nat.source not in firewalls:
        expr.append(_ifname("iifname", _iface_value(ctx, nat.source, interfaces)))
    expr += _nat_l4_matches(nat.proto, nat.dport, ctx)
    expr.append(_dnat_target(host, remap_port))
    return _rule("prerouting", expr, table=_NAT_TABLE)


def _forward_accept(
    nat: Nat,
    host: str,
    remap_port: str | None,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    ctx: str,
) -> _Command:
    """The filter forward accept admitting the post-DNAT connection to the internal host.

    Reuses the ADR-0006/0007 zone matching (iifname source, oifname dest), narrows on the internal
    ``ip daddr``, and matches the effective (remapped, else external) destination port.
    """
    chain, expr = _chain_and_zone_matches(nat.source, nat.dest, interfaces, firewalls, ctx)
    expr.append(_addr_match("daddr", host))
    effective_dport = remap_port if remap_port is not None else nat.dport
    expr += _nat_l4_matches(nat.proto, effective_dport, ctx)
    expr.append(_accept())
    return _rule(chain, expr)


def _nat_l4_matches(proto: str | None, dport: str | None, ctx: str) -> list[_Command]:
    """A ``<proto> dport`` match, a bare ``l4proto`` when portless, or []; a lone port fails."""
    if proto is None:
        if dport is not None:
            raise ConfigError(f"{ctx}: a port match needs a protocol")
        return []
    if dport is None:
        return [_l4proto(proto)]
    return [_port_match(proto, "dport", dport)]


def _dnat_target(host: str, remap_port: str | None) -> _Command:
    """``dnat to <host>[:<port>]``; ``family`` pins it to IPv4 without a ``meta nfproto`` guard."""
    target: dict[str, Any] = {"addr": host, "family": "ip"}
    if remap_port is not None:
        target["port"] = _port_value(remap_port)
    return {"dnat": target}


def _nat_table() -> _Command:
    return {"add": {"table": {"family": _FAMILY, "name": _NAT_TABLE}}}


def _nat_chain(name: str, prio: int) -> _Command:
    return {
        "add": {
            "chain": {
                "family": _FAMILY,
                "table": _NAT_TABLE,
                "name": name,
                "type": "nat",
                "hook": name,
                "prio": prio,
                "policy": "accept",
            }
        }
    }


# ---- base skeleton (ADR-0005) -----------------------------------------------------------


def _table() -> _Command:
    return {"add": {"table": {"family": _FAMILY, "name": _TABLE}}}


def _chain(name: str, policy: str) -> _Command:
    return {
        "add": {
            "chain": {
                "family": _FAMILY,
                "table": _TABLE,
                "name": name,
                "type": "filter",
                "hook": name,
                "prio": 0,
                "policy": policy,
            }
        }
    }


def _rule(chain: str, expr: list[_Command], table: str = _TABLE) -> _Command:
    return {"add": {"rule": {"family": _FAMILY, "table": table, "chain": chain, "expr": expr}}}


def _ct_established_related() -> _Command:
    return {
        "match": {
            "op": "in",
            "left": {"ct": {"key": "state"}},
            "right": {"set": ["established", "related"]},
        }
    }


def _ifname(key: str, value: str | dict[str, Any]) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": value}}


def _accept() -> _Command:
    return {"accept": None}
