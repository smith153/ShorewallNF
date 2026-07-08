"""Validator — semantic checks over the IR, the pure core stage before the Generator.

Validation runs up front (ARCHITECTURE.md) so the compiler fails fast with one clear,
actionable error rather than emitting a ruleset with a dead or misleading rule
(CLAUDE.md: a compiler that emits wrong firewall rules is worse than one that refuses).
It is a pure ``IR -> IR`` function (module-layout.md): it returns the ruleset unchanged
when every check passes, and raises :class:`~shorewallnf.errors.ConfigError` otherwise.

Checks so far:

- **ESTABLISHED/RELATED base-accept shadow (#138).** ADR-0005's base chains accept
  ``ct state {established, related}`` before any feature rule, so a ``DROP``/``REJECT`` in the
  ESTABLISHED or RELATED ``?SECTION`` is unreachable. Reject it; an ``ACCEPT`` there is a
  redundant no-op and is allowed. (A FASTACCEPT-off mode that made the base accept conditional
  is out of scope — a future ADR if a real need for mid-connection policy arrives.)
- **Malformed proto/port combinations (#317).** A ``dport``/``sport`` needs a port-bearing
  protocol: reject a port given with no ``proto``, and a source port given with ``icmp``/
  ``ipv6-icmp`` (which carry a *type* in the dest-port column, not a port — ADR-0007). Both
  are high-signal user mistakes the Generator would otherwise reject unlocated; catching them
  here cites ``file:line``. Full port-semantics modelling is out of scope (YAGNI).
"""

from __future__ import annotations

from .errors import ConfigError
from .ir import Provider, Rule, Ruleset

# ESTABLISHED/RELATED are accepted by the ADR-0005 base chain before any feature rule; INVALID
# and NEW are not, so a DROP/REJECT there is reachable and unaffected.
_BASE_ACCEPTED_SECTIONS = frozenset({"ESTABLISHED", "RELATED"})
_REJECTING_ACTIONS = frozenset({"DROP", "REJECT"})

# ICMP/ICMPv6 have no L4 ports: the DEST PORT column carries an ICMP *type* (ADR-0007), so a
# SOURCE PORT is meaningless there.
_PORTLESS_PROTOS = frozenset({"icmp", "ipv6-icmp"})


def validate(ruleset: Ruleset) -> Ruleset:
    """Run every semantic check over ``ruleset``; return it unchanged, or raise ``ConfigError``."""
    for rule in ruleset.rules:
        _reject_shadowed_section_rule(rule)
        _reject_malformed_proto_port(rule)
    _validate_providers(ruleset.providers, {iface.name for iface in ruleset.interfaces})
    return ruleset


def _reject_malformed_proto_port(rule: Rule) -> None:
    """Fail fast on a port that its protocol can't carry (#317, ADR-0004).

    Two high-signal mistakes: a ``dport``/``sport`` with no ``proto`` at all, and a source port
    on ``icmp``/``ipv6-icmp`` (which have no ports — the dest-port column is the ICMP type).
    """
    if rule.proto is None:
        if rule.dport is not None or rule.sport is not None:
            port = rule.dport if rule.dport is not None else rule.sport
            raise ConfigError(
                f"rule {rule.action} {rule.source!r} {rule.dest!r}: port {port!r} needs a "
                f"protocol — add a port-bearing proto (e.g. tcp/udp) to the PROTO column",
                path=rule.path,
                line=rule.line,
            )
        return
    if rule.proto in _PORTLESS_PROTOS and rule.sport is not None:
        raise ConfigError(
            f"rule {rule.action} {rule.source!r} {rule.dest!r}: {rule.proto} has no source "
            f"port {rule.sport!r} — ICMP carries a type in the dest-port column, not a port",
            path=rule.path,
            line=rule.line,
        )


def _validate_providers(
    providers: tuple[Provider, ...], interface_names: set[str]
) -> None:
    """Reject inconsistent ``providers`` definitions (#233, ADR-0004, epic #204).

    Fail fast on a fwmark or routing-table number reused across providers (both must be unique to
    steer traffic deterministically) or an interface naming no configured ``Interface``. Each is a
    single actionable error naming the collision / unknown reference.
    """
    marks: dict[int, str] = {}
    numbers: dict[int, str] = {}
    for provider in providers:
        _reject_reserved_or_out_of_range(provider)
        if provider.mark in marks:
            raise ConfigError(
                f"provider {provider.name!r} reuses fwmark {provider.mark} already assigned to "
                f"provider {marks[provider.mark]!r} — each provider needs a distinct mark",
                path=provider.path,
                line=provider.line,
            )
        marks[provider.mark] = provider.name
        if provider.number in numbers:
            raise ConfigError(
                f"provider {provider.name!r} reuses routing-table number {provider.number} "
                f"already assigned to provider {numbers[provider.number]!r} — each provider needs "
                f"a distinct number",
                path=provider.path,
                line=provider.line,
            )
        numbers[provider.number] = provider.name
        if provider.interface not in interface_names:
            raise ConfigError(
                f"provider {provider.name!r} names unknown interface {provider.interface!r} "
                f"(no such interface is configured)",
                path=provider.path,
                line=provider.line,
            )


# The kernel's reserved routing tables (iproute2): 0 unspec, 253 default, 254 main, 255 local.
# A provider must never claim one — teardown's ``ip route flush table <n>`` would wipe a system
# table. Marks and table ids are 32-bit unsigned.
_RESERVED_TABLE_IDS = frozenset({0, 253, 254, 255})
_MAX_U32 = 0xFFFFFFFF
# The top 32-bit value is reserved for the transparent-proxy mark/table (ADR-0051): the generator
# injects fwmark 0xFFFFFFFF into table 0xFFFFFFFF for TPROXY/DIVERT local delivery. A provider
# claiming it would let a tproxy'd packet select the provider's table instead of the local-delivery
# table (silent misroute), so we cap the provider space one below it. ir.TPROXY_MARK/TPROXY_TABLE_ID
# (added under #289) is the same value; use the literal here to avoid coupling to that concurrent
# change.
_TPROXY_RESERVED = 0xFFFFFFFF
_MAX_PROVIDER = _MAX_U32 - 1  # 0xFFFFFFFE


def _reject_reserved_or_out_of_range(provider: Provider) -> None:
    """Reject a provider whose routing-table number or fwmark is reserved/zero or out of range.

    A reserved table id (0/253/254/255) would let teardown flush a system routing table, and
    fwmark 0 matches unmarked traffic (silently routing everything out the provider) — both
    footguns the applier (#235) would faithfully carry out, so the gate belongs here (#255,
    ADR-0004). The top value 0xFFFFFFFF is reserved for the tproxy mark/table (ADR-0051, #290),
    so the accepted provider range stops at 0xFFFFFFFE.
    """
    if provider.number in _RESERVED_TABLE_IDS or not 1 <= provider.number <= _MAX_PROVIDER:
        raise ConfigError(
            f"provider {provider.name!r} uses reserved/invalid routing-table number "
            f"{provider.number} — use 1..{_MAX_PROVIDER} (0x{_MAX_PROVIDER:x}) excluding the "
            f"kernel-reserved {sorted(_RESERVED_TABLE_IDS)} (unspec/default/main/local) and "
            f"0x{_TPROXY_RESERVED:x} (reserved for the tproxy table, ADR-0051); one of those "
            "would let teardown flush a system routing table or steal tproxy local delivery",
            path=provider.path,
            line=provider.line,
        )
    if not 1 <= provider.mark <= _MAX_PROVIDER:
        raise ConfigError(
            f"provider {provider.name!r} uses invalid fwmark {provider.mark} — use "
            f"1..{_MAX_PROVIDER} (0x{_MAX_PROVIDER:x}); 0 matches unmarked traffic (silently "
            f"routing everything out this provider) and 0x{_TPROXY_RESERVED:x} is reserved for "
            "the tproxy mark (ADR-0051)",
            path=provider.path,
            line=provider.line,
        )


def _reject_shadowed_section_rule(rule: Rule) -> None:
    """Fail fast on a ``DROP``/``REJECT`` in an ESTABLISHED/RELATED section (#138, ADR-0005)."""
    section = (rule.section or "").upper()
    if section in _BASE_ACCEPTED_SECTIONS and rule.action in _REJECTING_ACTIONS:
        raise ConfigError(
            f"rule {rule.action} {rule.source!r} {rule.dest!r}: {rule.action} in the "
            f"{section} section is unreachable — established/related traffic is already "
            f"accepted by the base chain (ADR-0005), so this rule is dead. Remove it "
            f"(mid-connection DROP/REJECT is not supported).",
            path=rule.path,
            line=rule.line,
        )
