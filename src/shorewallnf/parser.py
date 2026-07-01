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

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import NamedTuple, TypeVar

from .errors import ConfigError
from .ir import Family, Interface, Zone, ZoneMember
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

    Each row is ``ZONE INTERFACE [BROADCAST] [OPTIONS]``; the broadcast column is ignored and
    options are comma-split. A ``-`` zone means the device belongs to no zone. A reference to an
    unknown zone, or a missing interface, fails fast with :class:`ConfigError`. Directive rows
    (``?FORMAT``/``?SECTION``, preserved by the preprocessor) are skipped — interfaces don't use
    them; the rules parser will interpret ``?SECTION`` itself.
    """
    zone_names = {zone.name for zone in zones}
    new_members: dict[str, list[ZoneMember]] = {}

    def attach_membership(interface: Interface, record: Record) -> None:
        zone = record.fields[0]
        if zone == "-":
            return
        if zone not in zone_names:
            raise ConfigError(f"unknown zone {zone!r}", path=record.path, line=record.line)
        member = ZoneMember(interface=interface.name, family=Family.BOTH)
        new_members.setdefault(zone, []).append(member)

    data = [record for record in records if not record.fields[0].startswith("?")]
    interfaces = tuple(build_records(data, _build_interface, attach_membership))
    populated = tuple(
        replace(zone, members=zone.members + tuple(new_members[zone.name]))
        if zone.name in new_members
        else zone
        for zone in zones
    )
    return ParsedInterfaces(interfaces=interfaces, zones=populated)


def _build_interface(record: Record) -> Interface:
    device = require_field(record, 1, "interface")
    options = tuple(record.fields[3].split(",")) if len(record.fields) > 3 else ()
    return Interface(name=device, options=options)
