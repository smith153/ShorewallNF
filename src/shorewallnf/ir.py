"""Family-aware intermediate representation (IR) core.

The nftables-agnostic model the compiler builds and the Generator consumes. Modeled per
ADR-0001 (frozen stdlib ``dataclasses`` — immutable, no I/O) and ADR-0002 (a single
family-aware model; family is data on the IR, scoped as ``both``/``ipv4``/``ipv6``).

This module holds the datatypes — the :class:`Family` scoping enum, :class:`Zone` (with its
:class:`ZoneMember` records), and the :class:`Interface`, :class:`Policy`, :class:`Rule` and
:class:`Nat` records the Generator consumes. These are datatype **shapes**; each feature epic
owns the deep per-file semantics (which options/actions are valid, how fields are populated).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Family(Enum):
    """Address family an IR construct scopes to (ADR-0002).

    ``BOTH`` is dual-stack: the Generator emits it once in the ``inet`` table with no
    family guard, so it matches IPv4 and IPv6 naturally. ``IPV4``/``IPV6`` scope to one
    family. (The nftables output table is always ``inet``; that is a Generator concern,
    not an IR scoping value — hence there is no ``INET`` member here.)
    """

    BOTH = "both"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class ZoneMember:
    """One way a zone is populated (ADR-0002: family lives on membership, not the zone).

    A bare interface (``host is None``) is dual-stack (``Family.BOTH``); a host/CIDR entry
    carries the family of its literal (``Family.IPV4`` or ``Family.IPV6``). A zone is
    therefore dual, v4-only, or v6-only as an emergent consequence of its members.
    """

    interface: str
    family: Family
    host: str | None = None


@dataclass(frozen=True, slots=True)
class Zone:
    """A named zone — one family-independent identity (ADR-0002).

    Family is not modeled on the zone; it lives on each :class:`ZoneMember`. ``is_firewall``
    marks the single ``firewall``-type zone (Shorewall's ``$FW``) — the firewall host itself,
    which has no interface members, so ``members`` defaults to empty.
    """

    name: str
    members: tuple[ZoneMember, ...] = ()
    is_firewall: bool = False


@dataclass(frozen=True, slots=True)
class Interface:
    """A network interface (device) and its options.

    Zone membership is not modeled here — it lives on :class:`ZoneMember`. Which option
    tokens are valid is the zones/interfaces epic's concern.
    """

    name: str
    options: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Policy:
    """A default policy for traffic from one zone to another (the ``policy`` file)."""

    source: str
    dest: str
    action: str
    log_level: str | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    """A single firewall rule, carrying the family it scopes to (ADR-0002).

    ``family`` defaults to ``both``: the Generator emits such a rule once in the ``inet``
    table with no family guard. A literal address or family-specific protocol narrows it to
    ``ipv4``/``ipv6`` (inferred by the parser, not here).
    """

    action: str
    source: str
    dest: str
    proto: str | None = None
    dport: str | None = None
    family: Family = Family.BOTH


@dataclass(frozen=True, slots=True)
class Nat:
    """A NAT entry (``DNAT``/``SNAT``/``MASQUERADE``).

    IPv4 by construction (ADR-0002): IPv6 does no NAT — its equivalent is a direct
    ``ACCEPT``. Hence ``family`` is a fixed :data:`Family.IPV4`, not a field.
    """

    action: str
    source: str
    dest: str
    to: str | None = None

    @property
    def family(self) -> Family:
        return Family.IPV4


@dataclass(frozen=True, slots=True)
class Ruleset:
    """Top-level IR container. Immutable; built once by the parser.

    Collections are tuples, not lists, to keep the whole structure immutable.
    """

    zones: tuple[Zone, ...] = ()
    interfaces: tuple[Interface, ...] = ()
    policies: tuple[Policy, ...] = ()
    rules: tuple[Rule, ...] = ()
    nats: tuple[Nat, ...] = ()
