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
from .ir import Family, Interface, Policy, Rule, Ruleset, Zone, ZoneMember
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
    return Policy(source=source, dest=dest, action=action, log_level=log_level)


_RULE_ACTIONS = frozenset({"ACCEPT", "DROP", "REJECT"})
_UNSET = "-"  # Shorewall's "column not specified" placeholder


def parse_rules(records: Iterable[Record], zones: tuple[Zone, ...]) -> tuple[Rule, ...]:
    """Parse ``rules``-file records into :class:`~shorewallnf.ir.Rule` IR (epic #74).

    Each data row is ``<ACTION> <SOURCE> <DEST> [PROTO] [DEST PORT] [SOURCE PORT]``; ``-`` marks
    an unspecified column. SOURCE/DEST are a bare ``zone`` or ``zone:host`` (host an IPv4/IPv6
    address or CIDR literal). ``?SECTION`` rows set the section attached to the rules that follow
    (``None`` before the first marker). Family is inferred per ADR-0002 — a host literal or
    ``icmp``/``ipv6-icmp`` pins the family; mixed families, an unknown action/zone, an
    unsupported host form, or trailing (unsupported) columns fail fast with a located
    :class:`ConfigError`.
    """
    zone_names = {zone.name for zone in zones}
    rules: list[Rule] = []
    section: str | None = None
    for record in records:
        if record.fields[0].startswith("?"):
            if record.fields[0].lower() == "?section":
                section = require_field(record, 1, "section name")
            continue  # other directives configure parsing; they are not rule rows
        rules.append(_build_rule(record, section, zone_names))
    return tuple(rules)


def _build_rule(record: Record, section: str | None, zone_names: set[str]) -> Rule:
    action = require_field(record, 0, "rule action")
    if action not in _RULE_ACTIONS:
        raise ConfigError(
            f"unknown rule action {action!r} (only ACCEPT/DROP/REJECT supported)",
            path=record.path,
            line=record.line,
        )
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
    are parsed first so ``interfaces`` can validate references and attach membership (the
    ``interfaces`` result carries the zones with their members populated). Files absent from
    ``streams`` are simply skipped.
    """
    zones: tuple[Zone, ...] = ()
    interfaces: tuple[Interface, ...] = ()
    if "zones" in streams:
        zones = parse_zones(parse(streams["zones"]))
    if "interfaces" in streams:
        parsed = parse_interfaces(parse(streams["interfaces"]), zones)
        zones, interfaces = parsed.zones, parsed.interfaces
    return Ruleset(zones=zones, interfaces=interfaces)
