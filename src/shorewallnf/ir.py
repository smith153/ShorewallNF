"""Family-aware intermediate representation (IR) core.

The nftables-agnostic model the compiler builds and the Generator consumes. Modeled per
ADR-0001 (frozen stdlib ``dataclasses`` — immutable, no I/O) and ADR-0002 (a single
family-aware model; family is data on the IR, scoped as ``both``/``ipv4``/``ipv6``).

This module holds the core datatypes — the :class:`Family` scoping enum and :class:`Zone`
(with its :class:`ZoneMember` records). The remaining datatypes (interfaces, policies,
rules, NAT) build on these in later tasks.
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

    Family is not modeled on the zone; it lives on each :class:`ZoneMember`. The special
    firewall zone (``$FW``) has no interface members, so ``members`` defaults to empty.
    """

    name: str
    members: tuple[ZoneMember, ...] = ()


@dataclass(frozen=True, slots=True)
class Ruleset:
    """Top-level IR container. Immutable; built once by the parser.

    Collections are tuples, not lists, to keep the whole structure immutable.
    """

    zones: tuple[Zone, ...] = ()
