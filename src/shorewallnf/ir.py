"""Minimal, family-aware intermediate representation (IR) stub.

Demonstrates the modeling approach chosen in ADR-0001: frozen stdlib
``dataclasses`` for immutable, nftables-agnostic data. The full IR (interfaces,
policies, rules, NAT, ...) is built out by later tasks — see the parsing-framework
epic. This module only establishes the pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Family(Enum):
    """Address family a construct applies to."""

    INET = "inet"  # dual-stack (both IPv4 and IPv6)
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class Zone:
    """A named network zone (e.g. ``net``, ``loc``, ``dmz``), scoped to a family."""

    name: str
    family: Family


@dataclass(frozen=True, slots=True)
class Ruleset:
    """Top-level IR container. Immutable; built once by the parser.

    Collections are tuples, not lists, to keep the whole structure immutable.
    """

    zones: tuple[Zone, ...] = ()
