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

from .conntrack import BUILTIN_HELPERS
from .errors import ConfigError
from .ir import (
    ConntrackHelper,
    Family,
    HelperDef,
    Interface,
    MacroDef,
    MacroRule,
    MangleRule,
    Nat,
    Policy,
    Provider,
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
    return Zone(
        name=name,
        is_firewall=zone_type == "firewall",
        path=record.path,
        line=record.line,
    )


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
                ZoneMember(
                    interface=device,
                    family=Family.BOTH,
                    path=record.path,
                    line=record.line,
                )
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
    return Policy(
        source=source,
        dest=dest,
        action=action,
        log_level=log_level,
        path=record.path,
        line=record.line,
    )


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
        path=record.path,
        line=record.line,
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
        path=record.path, line=record.line,
    )


def parse_stopped_rules(
    records: Iterable[Record], zones: tuple[Zone, ...]
) -> tuple[Rule, ...]:
    """Parse ``stoppedrules``-file rows into admin-access filter :class:`~shorewallnf.ir.Rule`s.

    The ``stoppedrules`` file declares the traffic permitted while the firewall is stopped
    (e.g. SSH from a management host). It shares the ``rules``-file grammar, so this reuses
    :func:`parse_rules` — but it is filter-only: a ``DNAT`` row has no meaning in the stopped
    safe state and fails fast with a located :class:`ConfigError` (ADR-0004). Family is inferred
    per ADR-0002 exactly as for ``rules``. An empty/absent file yields an empty tuple.
    """
    records = list(records)
    for record in records:
        if record.fields[0] in _NAT_ACTIONS:
            raise ConfigError(
                f"{record.fields[0]} is not allowed in stoppedrules "
                "(admin-access filter rules only)",
                path=record.path,
                line=record.line,
            )
    return parse_rules(records, zones).rules


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
        path=record.path,
        line=record.line,
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


# --- conntrack (helper assignment) parser ------------------------------------

_CT_HELPER_PREFIX = "CT:helper:"


def parse_conntrack(
    records: Iterable[Record], zones: tuple[Zone, ...]
) -> tuple[ConntrackHelper, ...]:
    """Parse ``conntrack``-file ``CT:helper:<name>`` rows into
    :class:`~shorewallnf.ir.ConntrackHelper` IR entries (epic #200, ADR-0040).

    A row is ``CT:helper:<name> <SOURCE> <DEST> [PROTO] [DEST PORT]``. ``<name>`` is resolved
    against the built-in registry (:data:`shorewallnf.conntrack.BUILTIN_HELPERS`) for its
    default proto/port and family capability. ``SOURCE``/``DEST`` are ``-`` or a
    ``zone``/``zone:host`` narrowing token; ``PROTO``/``DEST PORT`` override the registry
    defaults when given. Family follows the registry capability (ADR-0002), narrowed further by
    a v4/v6 host literal in ``SOURCE``/``DEST``. An unknown helper name, a non-``CT:helper``
    action (``notrack``/raw-table exemptions are out of scope for this epic), an unknown zone,
    a v6 literal on a v4-only helper, or a trailing (SPORT/…) column fails fast with a located
    :class:`ConfigError` rather than being silently dropped.
    """
    zone_names = {zone.name for zone in zones}
    return tuple(_build_conntrack_helper(record, zone_names) for record in records)


def _build_conntrack_helper(record: Record, zone_names: set[str]) -> ConntrackHelper:
    action = require_field(record, 0, "conntrack action")
    if not action.startswith(_CT_HELPER_PREFIX):
        raise ConfigError(
            f"unsupported conntrack action {action!r} "
            f"(only {_CT_HELPER_PREFIX}<name> helper assignment is supported; "
            "notrack/raw-table exemptions are out of scope)",
            path=record.path,
            line=record.line,
        )
    name = action[len(_CT_HELPER_PREFIX) :]
    helper = BUILTIN_HELPERS.get(name)
    if helper is None:
        raise ConfigError(
            f"unknown conntrack helper {name!r} (known helpers: {sorted(BUILTIN_HELPERS)})",
            path=record.path,
            line=record.line,
        )
    if len(record.fields) > 5:
        raise ConfigError(
            f"unsupported trailing conntrack columns {record.fields[5:]!r} "
            "(only action, source, dest, proto, dest-port are supported)",
            path=record.path,
            line=record.line,
        )
    source = _optional(record, 1)
    dest = _optional(record, 2)
    for token in (source, dest):  # `-` (unspecified) is not a zone reference to validate
        if token is not None:
            zone = token.split(":", 1)[0]
            if zone != "all" and zone not in zone_names:
                raise ConfigError(
                    f"unknown zone {zone!r}", path=record.path, line=record.line
                )
    proto = _optional(record, 3)
    proto = proto.lower() if proto is not None else helper.proto
    dport = _optional(record, 4) or ",".join(helper.ports)
    return ConntrackHelper(
        name=name,
        source=source or "",
        dest=dest or "",
        proto=proto,
        dport=dport,
        family=_resolve_helper_family(helper, source, dest, record),
    )


def _resolve_helper_family(
    helper: HelperDef, source: str | None, dest: str | None, record: Record
) -> Family:
    """Resolve a helper row's family: the registry capability (ADR-0002), narrowed by a v4/v6
    host literal in ``SOURCE``/``DEST``. A literal that conflicts with the capability (e.g. a v6
    address on a v4-only helper) fails fast."""
    capability = helper.family_capability
    literal = _infer_family(source or _UNSET, dest or _UNSET, None, record)
    if literal is Family.BOTH:
        return capability
    if capability is not Family.BOTH and literal is not capability:
        raise ConfigError(
            f"conntrack helper {helper.name!r} supports {capability.value} only, "
            f"but the row is narrowed to {literal.value}",
            path=record.path,
            line=record.line,
        )
    return literal


# --- providers (policy-routing) parser ---------------------------------------


def parse_providers(records: Iterable[Record]) -> tuple[Provider, ...]:
    """Parse ``providers``-file rows into :class:`~shorewallnf.ir.Provider` IR (epic #204).

    A row is ``NAME NUMBER MARK INTERFACE GATEWAY [OPTIONS]``: ``NUMBER`` is the routing-table id
    and ``MARK`` the fwmark steered into it (both integers — decimal or ``0x`` hex); ``INTERFACE``
    the egress interface, ``GATEWAY`` the next-hop (an address literal or a non-literal like
    ``detect``), and ``OPTIONS`` an optional comma-separated list. File order is preserved. Family
    follows the gateway literal (ADR-0002). A missing required column, a non-integer number/mark,
    or an unsupported trailing column fails fast with a located :class:`ConfigError` (ADR-0004).
    Interface/mark/table-id cross-checks are a later task (#233).
    """
    return tuple(_build_provider(record) for record in records)


def _build_provider(record: Record) -> Provider:
    name = require_field(record, 0, "provider name")
    number = _require_int(record, 1, "provider number")
    mark = _require_int(record, 2, "provider mark")
    interface = require_field(record, 3, "provider interface")
    gateway = require_field(record, 4, "provider gateway")
    if len(record.fields) > 6:
        raise ConfigError(
            f"unsupported trailing providers columns {record.fields[6:]!r} "
            "(only name, number, mark, interface, gateway, options are supported)",
            path=record.path,
            line=record.line,
        )
    options_field = _optional(record, 5)
    options = tuple(options_field.split(",")) if options_field is not None else ()
    return Provider(
        name=name,
        number=number,
        mark=mark,
        interface=interface,
        gateway=gateway,
        options=options,
        family=_provider_family(gateway),
        path=record.path,
        line=record.line,
    )


def _require_int(record: Record, index: int, name: str) -> int:
    """Required field ``index`` parsed as an integer (decimal or ``0x`` hex), else fail fast.

    The field-reading counterpart to :func:`_int_or_fail` (which parses an already-extracted
    token): read the field, then defer the parse/error to the shared helper (ADR-0004)."""
    return _int_or_fail(require_field(record, index, name), name, record)


def _provider_family(gateway: str) -> Family:
    """A provider's family follows its gateway (ADR-0002): an IPv4/IPv6 literal narrows it; a
    non-literal gateway (e.g. ``detect``) leaves it dual-stack (:data:`Family.BOTH`)."""
    try:
        network = ipaddress.ip_network(gateway, strict=False)
    except ValueError:
        return Family.BOTH
    return Family.IPV4 if network.version == 4 else Family.IPV6


# --- mangle (packet marking) parser ------------------------------------------


def parse_mangle(records: Iterable[Record]) -> tuple[MangleRule, ...]:
    """Parse ``mangle``-file rows into :class:`~shorewallnf.ir.MangleRule` IR (epic #203).

    A row is ``ACTION SOURCE DEST [PROTO] [DPORT]``. ``ACTION`` is ``MARK(<value>[/<mask>])`` /
    ``CONNMARK(<value>[/<mask>])`` (packet/connection mark + optional mask), bare ``DIVERT``, or
    ``TPROXY(<port>)`` (transparent-proxy port; the mark is the reserved ``TPROXY_MARK`` the
    generator injects, not per-rule — ADR-0051); the rest are the match criteria. File order is
    preserved. Family is inferred from the row content (ADR-0002). An unknown action, a malformed
    target (non-integer/out-of-range port, or a per-rule tproxy mark), or an unsupported
    trailing column fails fast with a located :class:`ConfigError` (ADR-0004).
    """
    return tuple(_build_mangle_rule(record) for record in records)


def _build_mangle_rule(record: Record) -> MangleRule:
    action_token = require_field(record, 0, "mangle action")
    if len(record.fields) > 5:
        raise ConfigError(
            f"unsupported trailing mangle columns {record.fields[5:]!r} "
            "(only action, source, dest, proto, dest-port are supported)",
            path=record.path,
            line=record.line,
        )
    action, mark, mask, port = _parse_mangle_action(action_token, record)
    source = _optional(record, 1) or ""
    dest = _optional(record, 2) or ""
    proto = _optional(record, 3)
    dport = _optional(record, 4)
    return MangleRule(
        action=action,
        source=source,
        dest=dest,
        proto=proto,
        dport=dport,
        mark=mark,
        mask=mask,
        port=port,
        family=_infer_family(source, dest, proto, record),
        path=record.path,
        line=record.line,
    )


def _parse_mangle_action(
    token: str, record: Record
) -> tuple[str, int | None, int | None, int | None]:
    """Split a ``mangle`` ACTION column into ``(action, mark, mask, port)`` (ADR-0004)."""
    if token == "DIVERT":
        return "DIVERT", None, None, None
    for name in ("MARK", "CONNMARK"):
        if token.startswith(f"{name}(") and token.endswith(")"):
            mark, mask = _parse_mark_mask(token[len(name) + 1 : -1], name, record)
            return name, mark, mask, None
    if token.startswith("TPROXY(") and token.endswith(")"):
        port = _parse_tproxy(token[len("TPROXY(") : -1], record)
        # No per-rule mark: the tproxy mark is the reserved TPROXY_MARK the generator injects
        # (ADR-0051 Part A), not an operator value.
        return "TPROXY", None, None, port
    raise ConfigError(
        f"unsupported mangle action {token!r} "
        "(expected MARK(<value>), CONNMARK(<value>), DIVERT, or TPROXY(<port>))",
        path=record.path,
        line=record.line,
    )


def _parse_mark_mask(value: str, name: str, record: Record) -> tuple[int, int | None]:
    """Parse a ``MARK``/``CONNMARK`` ``<value>[/<mask>]`` parameter into ``(mark, mask)``."""
    if not value:
        raise ConfigError(
            f"{name} needs a mark value: {name}(<value>[/<mask>])",
            path=record.path,
            line=record.line,
        )
    mark_str, sep, mask_str = value.partition("/")
    mark = _int_or_fail(mark_str, f"{name} mark value", record)
    mask = _int_or_fail(mask_str, f"{name} mask", record) if sep else None
    return mark, mask


def _parse_tproxy(value: str, record: Record) -> int:
    """Parse a ``TPROXY`` ``<port>`` parameter into a port.

    ``TPROXY`` is markless in surface syntax: the tproxy mark is the reserved ``TPROXY_MARK`` the
    generator injects (ADR-0051 Part A), so a per-rule ``TPROXY(<port>,<mark>)`` is rejected
    fail-fast (ADR-0004) rather than silently ignored.
    """
    if not value:
        raise ConfigError(
            "TPROXY needs a port: TPROXY(<port>)",
            path=record.path,
            line=record.line,
        )
    port_str, sep, _mark = value.partition(",")
    if sep:
        raise ConfigError(
            "TPROXY takes no per-rule mark: the tproxy mark is the reserved TPROXY_MARK the "
            "generator injects (ADR-0051), not an operator value — use TPROXY(<port>)",
            path=record.path,
            line=record.line,
        )
    port = _int_or_fail(port_str, "TPROXY port", record)
    if not 1 <= port <= 65535:
        raise ConfigError(
            f"TPROXY port {port} out of range (1-65535)",
            path=record.path,
            line=record.line,
        )
    return port


def _int_or_fail(token: str, name: str, record: Record) -> int:
    """Parse ``token`` as an integer (decimal or ``0x`` hex), or fail fast (ADR-0004)."""
    try:
        return int(token, 0)
    except ValueError:
        raise ConfigError(
            f"{name} must be an integer, got {token!r}",
            path=record.path,
            line=record.line,
        ) from None


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
    conntrack_helpers: tuple[ConntrackHelper, ...] = ()
    if "conntrack" in streams:
        conntrack_helpers = parse_conntrack(parse(streams["conntrack"]), zones)
    providers: tuple[Provider, ...] = ()
    if "providers" in streams:
        providers = parse_providers(parse(streams["providers"]))
    mangle_rules: tuple[MangleRule, ...] = ()
    if "mangle" in streams:
        mangle_rules = parse_mangle(parse(streams["mangle"]))
    stopped_rules: tuple[Rule, ...] = ()
    if "stoppedrules" in streams:
        stopped_rules = parse_stopped_rules(parse(streams["stoppedrules"]), zones)
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
        stopped_rules=stopped_rules,
        nats=nats,
        conntrack_helpers=conntrack_helpers,
        providers=providers,
        mangle_rules=mangle_rules,
        actions=actions,
    )
