"""Parser — turns a preprocessed line stream into structured field-records.

The first pure-core parsing stage (ADR-0003): it consumes the preprocessor's
:class:`~shorewallnf.preprocessor.SourceLine` stream and yields nftables-agnostic
:class:`Record`\\ s — a line's whitespace/column-split fields tagged with the source
location the following stages report errors against. It handles the lexical concerns common
to every Shorewall tabular file (``#`` comments, blank lines, trailing-``\\`` continuation);
per-file *meaning* (which column is a zone, a proto, …) belongs to the per-file parsers built
on top of this. Malformed input fails fast with :class:`~shorewallnf.errors.ConfigError`.

It also provides the reusable **parse-to-IR scaffold** (:func:`build_records`,
:func:`require_field`): a per-file parser supplies a builder that maps one :class:`Record` to
one typed IR object and an optional validation hook for per-file semantic checks (e.g. ADR-0002
family consistency). The concrete builders live in the feature epics.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from typing import NamedTuple, TypeVar

from .errors import ConfigError
from .ir import (
    Family,
    Interface,
    MacroDef,
    MacroRule,
    Nat,
    Policy,
    Rule,
    Ruleset,
    Zone,
    ZoneMember,
)
from .preprocessor import SourceLine

_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class Record:
    """One logical config line: its split ``fields`` plus its source location.

    ``path``/``line`` point at the record's first physical line, so later stages can report
    ``file:line`` errors even after continuation lines were joined.
    """

    fields: tuple[str, ...]
    path: str
    line: int


def parse(lines: Iterable[SourceLine]) -> list[Record]:
    """Split each logical line into fields, dropping comments and blank lines.

    ``#`` starts a comment to end of line; a physical line whose (comment-stripped) content
    ends with ``\\`` continues onto the next. A continuation left open at end of input raises
    :class:`ConfigError` at the record's first line.
    """
    records: list[Record] = []
    segments: list[str] = []
    start: tuple[str, int] | None = None  # location of the pending record's first line

    for source in lines:
        content = source.text.partition("#")[0]  # strip inline/full-line comment
        continued = content.rstrip().endswith("\\")
        if start is None:
            start = (source.path, source.line)
        segments.append(content.rstrip()[:-1] if continued else content)
        if continued:
            continue
        fields = " ".join(segments).split()
        if fields:  # skip blank / comment-only logical lines
            records.append(Record(fields=tuple(fields), path=start[0], line=start[1]))
        segments = []
        start = None

    if start is not None:  # last line ended with an unterminated continuation
        raise ConfigError("unterminated line continuation", path=start[0], line=start[1])
    return records


def require_field(record: Record, index: int, name: str) -> str:
    """Return ``record.fields[index]``, or fail fast with the record's location if absent.

    The field accessor per-file builders use so a short line reports ``file:line: missing
    <name>`` rather than an opaque ``IndexError``.
    """
    try:
        return record.fields[index]
    except IndexError:
        raise ConfigError(f"missing {name}", path=record.path, line=record.line) from None


def build_records(
    records: Iterable[Record],
    builder: Callable[[Record], _T],
    validate: Callable[[_T, Record], None] | None = None,
) -> list[_T]:
    """Map each field-record to a typed IR object, the reusable parse-to-IR scaffold.

    ``builder`` turns one :class:`Record` into one IR object (using :func:`require_field` for
    located errors). ``validate``, if given, is the **per-file semantic hook**: it runs on
    each built object with its source ``record`` (so it can raise a located
    :class:`ConfigError` — e.g. rejecting a rule that mixes IPv4 and IPv6 literals, ADR-0002).
    """
    result: list[_T] = []
    for record in records:
        obj = builder(record)
        if validate is not None:
            validate(obj, record)
        result.append(obj)
    return result


# --- per-file parsers (built on the scaffold above) --------------------------

_ZONE_TYPES = frozenset({"ipv4", "ipv6", "firewall"})


def parse_zones(records: Iterable[Record]) -> tuple[Zone, ...]:
    """Parse ``zones``-file records (``<name> <type>``) into :class:`~shorewallnf.ir.Zone` IR.

    Per ADR-0002 the ``ipv4``/``ipv6`` type does **not** put a family on the zone (family lives
    on membership); the ``firewall`` type marks the ``$FW`` zone via ``is_firewall``. A short
    line, an unknown type, or a duplicate zone name fails fast with :class:`ConfigError`.
    """
    seen: set[str] = set()

    def reject_duplicate(zone: Zone, record: Record) -> None:
        if zone.name in seen:
            raise ConfigError(
                f"duplicate zone {zone.name!r}", path=record.path, line=record.line
            )
        seen.add(zone.name)

    return tuple(build_records(records, _build_zone, reject_duplicate))


def _build_zone(record: Record) -> Zone:
    name = require_field(record, 0, "zone name")
    zone_type = require_field(record, 1, "zone type")
    if zone_type not in _ZONE_TYPES:
        raise ConfigError(
            f"unknown zone type {zone_type!r}", path=record.path, line=record.line
        )
    return Zone(name=name, is_firewall=zone_type == "firewall")


class ParsedInterfaces(NamedTuple):
    """The `interfaces` parse result: the devices, plus the zones with their membership."""

    interfaces: tuple[Interface, ...]
    zones: tuple[Zone, ...]


def parse_interfaces(records: Iterable[Record], zones: tuple[Zone, ...]) -> ParsedInterfaces:
    """Parse ``interfaces``-file records into :class:`~shorewallnf.ir.Interface` IR and attach
    dual-stack :class:`~shorewallnf.ir.ZoneMember`\\ s to the named zones (ADR-0002).

    Each row is ``ZONE INTERFACE [BROADCAST] OPTIONS``; the OPTIONS column depends on the active
    ``?FORMAT`` (which the preprocessor preserves in the stream): FORMAT 1 (the default) has a
    BROADCAST column so OPTIONS is field 3, FORMAT 2 drops BROADCAST so OPTIONS is field 2. A
    ``-`` zone means the device belongs to no zone. An unsupported ``?FORMAT``, an unknown zone,
    or a missing interface fails fast with :class:`ConfigError`. Other directive rows
    (``?SECTION``) are skipped — the rules parser interprets those itself.
    """
    zone_names = {zone.name for zone in zones}
    new_members: dict[str, list[ZoneMember]] = {}
    interfaces: list[Interface] = []
    options_field = 3  # FORMAT 1 default: ZONE INTERFACE BROADCAST OPTIONS

    for record in records:
        head = record.fields[0]
        if head.startswith("?"):
            if head.lower() == "?format":
                options_field = _interfaces_options_field(record)
            continue  # directive rows configure parsing; they are not interface entries
        device = require_field(record, 1, "interface")
        options = (
            tuple(record.fields[options_field].split(","))
            if len(record.fields) > options_field
            else ()
        )
        interfaces.append(Interface(name=device, options=options))
        if head != "-":  # "-" is Shorewall's no-zone marker (e.g. an ifb device)
            if head not in zone_names:
                raise ConfigError(f"unknown zone {head!r}", path=record.path, line=record.line)
            new_members.setdefault(head, []).append(
                ZoneMember(interface=device, family=Family.BOTH)
            )

    populated = tuple(
        replace(zone, members=zone.members + tuple(new_members[zone.name]))
        if zone.name in new_members
        else zone
        for zone in zones
    )
    return ParsedInterfaces(interfaces=tuple(interfaces), zones=populated)


def _interfaces_options_field(directive: Record) -> int:
    """Map a ``?FORMAT n`` row to the OPTIONS column index for the interface rows that follow.

    FORMAT 1 (BROADCAST present) → field 3; FORMAT 2 (no BROADCAST) → field 2. The preprocessor
    already validated ``n`` is a positive integer; only 1 and 2 are meaningful for ``interfaces``.
    """
    fmt = directive.fields[1]
    if fmt == "1":
        return 3
    if fmt == "2":
        return 2
    raise ConfigError(
        f"unsupported ?FORMAT {fmt} for interfaces (expected 1 or 2)",
        path=directive.path,
        line=directive.line,
    )


_POLICY_ACTIONS = frozenset({"ACCEPT", "DROP", "REJECT"})
# nft `log level` keywords (plus `audit`). Shorewall's syslog spellings (`warning`/`error`/
# `panic`), numeric levels, and NFLOG/ULOG targets are not these; reject them (#117, fail-fast)
# rather than emit a ruleset nft rejects. Translating them is deferred (YAGNI).
_LOG_LEVELS = frozenset(
    {"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug", "audit"}
)


def parse_policies(records: Iterable[Record], zones: tuple[Zone, ...]) -> tuple[Policy, ...]:
    """Parse ``policy``-file records (``<source> <dest> <action> [log_level]``) into
    :class:`~shorewallnf.ir.Policy` IR — the inter-zone default policies.

    ``source``/``dest`` must each be a known zone (the firewall zone included) or the wildcard
    ``all``. The action must be ``ACCEPT``/``DROP``/``REJECT``. A malformed line, unknown zone,
    or unknown action fails fast with :class:`ConfigError`.
    """
    zone_names = {zone.name for zone in zones}

    def check_zones(policy: Policy, record: Record) -> None:
        for zone in (policy.source, policy.dest):
            if zone != "all" and zone not in zone_names:
                raise ConfigError(f"unknown zone {zone!r}", path=record.path, line=record.line)

    return tuple(build_records(records, _build_policy, check_zones))


def _build_policy(record: Record) -> Policy:
    source = require_field(record, 0, "source zone")
    dest = require_field(record, 1, "dest zone")
    action = require_field(record, 2, "policy action")
    if action not in _POLICY_ACTIONS:
        raise ConfigError(
            f"unknown policy action {action!r}", path=record.path, line=record.line
        )
    if len(record.fields) > 4:
        # Shorewall's LIMIT:BURST / CONNLIMIT columns aren't supported yet — reject rather
        # than silently drop them (#94, fail-fast).
        raise ConfigError(
            f"unsupported trailing policy columns {record.fields[4:]!r} "
            "(only source, dest, action, log level are supported)",
            path=record.path,
            line=record.line,
        )
    log_level = record.fields[3] if len(record.fields) > 3 else None
    if log_level is not None and log_level not in _LOG_LEVELS:
        raise ConfigError(
            f"unsupported log level {log_level!r} (expected one of {sorted(_LOG_LEVELS)})",
            path=record.path,
            line=record.line,
        )
    return Policy(source=source, dest=dest, action=action, log_level=log_level)


_RULE_ACTIONS = frozenset({"ACCEPT", "DROP", "REJECT"})
_NAT_ACTIONS = frozenset({"DNAT"})  # SNAT/MASQUERADE are epic #76
_UNSET = "-"  # Shorewall's "column not specified" placeholder


class ParsedRules(NamedTuple):
    """The two IR streams a ``rules`` file yields: filter rules and ``DNAT`` nat entries."""

    rules: tuple[Rule, ...]
    nats: tuple[Nat, ...]


def parse_rules(records: Iterable[Record], zones: tuple[Zone, ...]) -> ParsedRules:
    """Parse ``rules``-file records into filter :class:`~shorewallnf.ir.Rule`s and ``DNAT``
    :class:`~shorewallnf.ir.Nat`s (epic #74 / #75).

    A filter row is ``<ACTION> <SOURCE> <DEST> [PROTO] [DEST PORT] [SOURCE PORT]``; a ``DNAT`` row
    is ``DNAT <SOURCE> <ZONE:HOST[:PORT]> [PROTO] [DEST PORT]``. ``-`` marks an unspecified column.
    SOURCE/DEST are a bare ``zone`` or ``zone:host`` (host an IPv4/IPv6 address or CIDR literal).
    ``?SECTION`` rows set the section attached to the filter rules that follow (``None`` before the
    first marker; sections don't apply to ``DNAT``). Family is inferred per ADR-0002 — a host
    literal or ``icmp``/``ipv6-icmp`` pins it; mixed families, an unknown action/zone, an
    unsupported host form, or trailing (unsupported) columns fail fast with a located
    :class:`ConfigError`.
    """
    zone_names = {zone.name for zone in zones}
    rules: list[Rule] = []
    nats: list[Nat] = []
    section: str | None = None
    for record in records:
        if record.fields[0].startswith("?"):
            if record.fields[0].lower() == "?section":
                section = require_field(record, 1, "section name")
            continue  # other directives configure parsing; they are not rule rows
        if record.fields[0] in _NAT_ACTIONS:
            nats.append(_build_nat(record, zone_names))
        else:
            rules.append(_build_rule(record, section, zone_names))
    return ParsedRules(tuple(rules), tuple(nats))


def _build_rule(record: Record, section: str | None, zone_names: set[str]) -> Rule:
    # The ACTION column is a plain str: a built-in verdict or a macro/action name (ADR-0020 §2).
    # The parser stays purely syntactic and macro-unaware — the resolver (#184) tells them apart
    # by registry lookup and fails fast on an unknown name, so no verdict check happens here.
    action = require_field(record, 0, "rule action")
    source = require_field(record, 1, "source")
    dest = require_field(record, 2, "dest")
    if len(record.fields) > 6:
        # ORIGINAL DEST / RATE LIMIT / USER-GROUP / MARK columns aren't supported yet — reject
        # rather than silently drop them (fail-fast, ADR-0004).
        raise ConfigError(
            f"unsupported trailing rule columns {record.fields[6:]!r} "
            "(only action, source, dest, proto, dest-port, source-port are supported)",
            path=record.path,
            line=record.line,
        )
    proto = _optional(record, 3)
    if proto is not None:
        proto = proto.lower()  # PROTO is case-insensitive; store nft's canonical lowercase (#134)
    _check_zones(source, dest, zone_names, record)
    return Rule(
        action=action,
        source=source,
        dest=dest,
        proto=proto,
        dport=_optional(record, 4),
        sport=_optional(record, 5),
        section=section,
        family=_infer_family(source, dest, proto, record),
    )


def _build_nat(record: Record, zone_names: set[str]) -> Nat:
    """Build a ``DNAT`` :class:`~shorewallnf.ir.Nat` from a ``DNAT <src> <zone:host[:port]>`` row.

    The target column is ``zone:host[:port]`` — ``zone`` the internal zone, ``host[:port]`` the DNAT
    target (an optional ``:port`` remaps the destination port), stored verbatim in ``to`` for the
    generator to split. Family is inferred structurally from the target literal (two or more colons
    ⇒ an IPv6 literal ⇒ :data:`Family.IPV6`, the direct-accept case #144), per ADR-0002.
    """
    action = require_field(record, 0, "rule action")
    source = require_field(record, 1, "source")
    target = require_field(record, 2, "DNAT target")
    if len(record.fields) > 5:
        raise ConfigError(
            f"unsupported trailing DNAT columns {record.fields[5:]!r} "
            "(only action, source, target, proto, dest-port are supported)",
            path=record.path,
            line=record.line,
        )
    zone, sep, host = target.partition(":")
    if not sep or not host:
        raise ConfigError(
            f"DNAT target {target!r} needs a host (zone:host[:port])",
            path=record.path,
            line=record.line,
        )
    for name in (source, zone):
        if name != "all" and name not in zone_names:
            raise ConfigError(f"unknown zone {name!r}", path=record.path, line=record.line)
    proto = _optional(record, 3)
    if proto is not None:
        proto = proto.lower()
    family = Family.IPV6 if host.count(":") >= 2 else Family.IPV4
    return Nat(
        action=action, source=source, dest=zone, to=host, proto=proto,
        dport=_optional(record, 4), family=family,
    )


def parse_snat(records: Iterable[Record]) -> tuple[Nat, ...]:
    """Parse ``snat``-file rows (``MASQUERADE``/``SNAT(<addr>)``) into source-NAT
    :class:`~shorewallnf.ir.Nat` entries (epic #76).

    A row is ``<ACTION> <SOURCE> <DEST>``: ``ACTION`` is ``MASQUERADE`` (dynamic source NAT to
    the egress interface's address) or ``SNAT(<addr>)`` (static source NAT to ``<addr>``);
    ``SOURCE`` the source network(s) — a comma-separated CIDR list preserved verbatim for the
    generator to expand; ``DEST`` the egress (out) interface. Source NAT is IPv4 by construction
    (ADR-0002: IPv6 does no NAT), so ``family`` is always :data:`Family.IPV4`. The ``snat`` file's
    narrowing columns (PROTO/PORT/IPSEC/MARK/PROBABILITY) are out of MVP scope (#76): a row that
    carries them fails fast with :class:`ConfigError` rather than being silently dropped.
    """
    return tuple(_build_snat(record) for record in records)


def _build_snat(record: Record) -> Nat:
    action = require_field(record, 0, "snat action")
    source_nets = require_field(record, 1, "snat source")
    out_interface = require_field(record, 2, "snat egress interface")
    if len(record.fields) > 3:
        raise ConfigError(
            f"unsupported trailing snat columns {record.fields[3:]!r} "
            "(only action, source, egress interface are supported; "
            "PROTO/PORT/IPSEC/MARK/PROBABILITY narrowing is out of scope)",
            path=record.path,
            line=record.line,
        )
    action, snat_to = _parse_snat_action(action, record)
    return Nat(
        action=action,
        source_nets=source_nets,
        out_interface=out_interface,
        snat_to=snat_to,
        family=Family.IPV4,
    )


def _parse_snat_action(token: str, record: Record) -> tuple[str, str | None]:
    """Split a ``snat`` ACTION column into ``(action, snat_to)``.

    ``MASQUERADE`` carries no address; ``SNAT(<addr>)`` yields ``("SNAT", <addr>)``. A bare
    ``SNAT``, an empty ``SNAT()``, or any other action fails fast (ADR-0004).
    """
    if token == "MASQUERADE":
        return "MASQUERADE", None
    if token.startswith("SNAT(") and token.endswith(")"):
        addr = token[len("SNAT(") : -1]
        if not addr:
            raise ConfigError(
                "SNAT action needs a source address: SNAT(<addr>)",
                path=record.path,
                line=record.line,
            )
        return "SNAT", addr
    raise ConfigError(
        f"unsupported snat action {token!r} (expected MASQUERADE or SNAT(<addr>))",
        path=record.path,
        line=record.line,
    )


# --- action.<Name> (site-defined macro/custom-action) parser -----------------


def parse_action(name: str, records: Iterable[Record]) -> MacroDef:
    """Parse a site-defined ``action.<Name>`` body into a :class:`~shorewallnf.ir.MacroDef`
    (ADR-0020, #182).

    Each body row is ``<ACTION> <SOURCE> <DEST> [PROTO] [DEST PORT] [SOURCE PORT]`` limited to
    the ``ACCEPT``/``DROP``/``REJECT`` verdict subset, mapping to a
    :class:`~shorewallnf.ir.MacroRule`. Per ADR-0020 a ``MacroRule`` has no source/dest — they
    come from the invoking rule — so the SOURCE and DEST columns must be the ``-`` placeholder;
    a non-``-`` value, an unsupported action, or a malformed row fails fast with a located
    :class:`ConfigError`. This is Reader→Parser only: no expansion/narrowing (that is the
    resolver, #184). Family is inferred per ADR-0002 from the proto column alone.
    """
    body = tuple(build_records(records, _build_macro_rule))
    return MacroDef(name=name, body=body, family=_combine_families(body))


def _build_macro_rule(record: Record) -> MacroRule:
    action = require_field(record, 0, "action")
    if action not in _RULE_ACTIONS:
        raise ConfigError(
            f"unsupported action {action!r} in action body "
            "(only ACCEPT/DROP/REJECT supported)",
            path=record.path,
            line=record.line,
        )
    source = require_field(record, 1, "source")
    dest = require_field(record, 2, "dest")
    for column, value in (("SOURCE", source), ("DEST", dest)):
        if value != _UNSET:
            raise ConfigError(
                f"action body {column} must be {_UNSET!r} "
                "(source/dest come from the invoking rule, ADR-0020)",
                path=record.path,
                line=record.line,
            )
    if len(record.fields) > 6:
        raise ConfigError(
            f"unsupported trailing action columns {record.fields[6:]!r} "
            "(only action, source, dest, proto, dest-port, source-port are supported)",
            path=record.path,
            line=record.line,
        )
    proto = _optional(record, 3)
    if proto is not None:
        proto = proto.lower()  # PROTO is case-insensitive; store nft's canonical lowercase
    return MacroRule(
        action=action,
        proto=proto,
        dport=_optional(record, 4),
        sport=_optional(record, 5),
        family=_family_from_proto(proto),
    )


def _family_from_proto(proto: str | None) -> Family:
    """Infer a family from the proto column alone (ADR-0002): ``icmp`` → IPv4,
    ``ipv6-icmp`` → IPv6, otherwise dual-stack :data:`Family.BOTH`. Since an action body's
    source/dest are ``-``, the proto is the only family hint."""
    if proto == "icmp":
        return Family.IPV4
    if proto == "ipv6-icmp":
        return Family.IPV6
    return Family.BOTH


def _combine_families(rules: tuple[MacroRule, ...]) -> Family:
    """The family scoping a whole :class:`~shorewallnf.ir.MacroDef`: the one family its body
    agrees on, else :data:`Family.BOTH` (an empty or mixed-family body is dual-stack)."""
    families = {rule.family for rule in rules}
    return families.pop() if len(families) == 1 else Family.BOTH


def _optional(record: Record, index: int) -> str | None:
    """Field ``index`` if present and not the ``-`` placeholder, else ``None``."""
    if index >= len(record.fields):
        return None
    value = record.fields[index]
    return None if value == _UNSET else value


def _check_zones(source: str, dest: str, zone_names: set[str], record: Record) -> None:
    for token in (source, dest):
        zone = token.split(":", 1)[0]
        if zone != "all" and zone not in zone_names:
            raise ConfigError(f"unknown zone {zone!r}", path=record.path, line=record.line)


def _infer_family(source: str, dest: str, proto: str | None, record: Record) -> Family:
    """Infer a rule's family (ADR-0002); mixed IPv4/IPv6 hints fail fast."""
    families: set[Family] = set()
    for token in (source, dest):
        _, sep, host = token.partition(":")
        if sep:
            families.add(_family_of_literal(host, record))
    if proto is not None:
        if proto.lower() == "icmp":
            families.add(Family.IPV4)
        elif proto.lower() == "ipv6-icmp":
            families.add(Family.IPV6)
    if not families:
        return Family.BOTH
    if len(families) > 1:
        raise ConfigError(
            f"rule mixes address families {sorted(f.value for f in families)}",
            path=record.path,
            line=record.line,
        )
    return families.pop()


def _family_of_literal(host: str, record: Record) -> Family:
    try:
        network = ipaddress.ip_network(host, strict=False)
    except ValueError:
        raise ConfigError(
            f"unsupported host {host!r} (expected an IPv4/IPv6 address or CIDR)",
            path=record.path,
            line=record.line,
        ) from None
    return Family.IPV4 if network.version == 4 else Family.IPV6


def parse_config(streams: Mapping[str, list[SourceLine]]) -> Ruleset:
    """Assemble a :class:`~shorewallnf.ir.Ruleset` from the preprocessed per-file streams.

    Dispatches each known config file to its per-file parser and combines the results. Zones
    are parsed first so ``interfaces`` can validate references and attach membership, then
    ``policy`` is validated against the populated zones (the ``interfaces`` result carries the
    zones with their members populated). Files absent from ``streams`` are simply skipped.
    """
    zones: tuple[Zone, ...] = ()
    interfaces: tuple[Interface, ...] = ()
    policies: tuple[Policy, ...] = ()
    rules: tuple[Rule, ...] = ()
    if "zones" in streams:
        zones = parse_zones(parse(streams["zones"]))
    if "interfaces" in streams:
        parsed = parse_interfaces(parse(streams["interfaces"]), zones)
        zones, interfaces = parsed.zones, parsed.interfaces
    if "policy" in streams:
        policies = parse_policies(parse(streams["policy"]), zones)
    nats: tuple[Nat, ...] = ()
    if "rules" in streams:
        parsed_rules = parse_rules(parse(streams["rules"]), zones)
        rules, nats = parsed_rules.rules, parsed_rules.nats
    if "snat" in streams:
        nats += parse_snat(parse(streams["snat"]))
    # Site-defined action.<Name> files → a name-keyed MacroDef registry (ADR-0020, #182),
    # built in name-sorted order so the registry is deterministic. The `actions` index file
    # is discovered by the reader but not a MacroDef, so it is not parsed here.
    actions = {
        name[len("action.") :]: parse_action(name[len("action.") :], parse(streams[name]))
        for name in sorted(streams)
        if name.startswith("action.")
    }
    return Ruleset(
        zones=zones,
        interfaces=interfaces,
        policies=policies,
        rules=rules,
        nats=nats,
        actions=actions,
    )
