"""Generator — the pure IR → nftables JSON stage (ADR-0001/0003).

Consumes the family-aware IR and emits the base ``inet`` skeleton as ``python3-nftables`` JSON:
one ``inet filter`` table, the fail-closed ``input``/``forward``/``output`` base chains, and the
always-on stateful + loopback accepts. The full layout and rationale are recorded in
[ADR-0005](../../docs/adr/0005-nftables-base-chain-layout.md); it is dual-stack by construction
(ADR-0002) and golden-file-testable without an ``nft`` binary.

The base skeleton is currently independent of ``ruleset`` content — later epics append zone sets
and per-feature rules built from it, which is why :func:`generate` already takes the ``Ruleset``.
"""

from __future__ import annotations

from typing import Any

from .ir import Ruleset

_FAMILY = "inet"
_TABLE = "filter"

# (chain name == hook name, base-chain policy). Input/forward fail closed; output accepts.
_BASE_CHAINS = (("input", "drop"), ("forward", "drop"), ("output", "accept"))

_Command = dict[str, Any]


def generate(ruleset: Ruleset) -> dict[str, list[_Command]]:
    """Emit the base ``inet`` nftables skeleton (ADR-0005) as ``python3-nftables`` JSON."""
    commands: list[_Command] = [_table()]
    commands += [_chain(name, policy) for name, policy in _BASE_CHAINS]
    commands.append(_rule("input", [_ct_established_related(), _accept()]))
    commands.append(_rule("input", [_iifname("lo"), _accept()]))
    commands.append(_rule("forward", [_ct_established_related(), _accept()]))
    return {"nftables": commands}


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


def _rule(chain: str, expr: list[_Command]) -> _Command:
    return {"add": {"rule": {"family": _FAMILY, "table": _TABLE, "chain": chain, "expr": expr}}}


def _ct_established_related() -> _Command:
    return {
        "match": {
            "op": "in",
            "left": {"ct": {"key": "state"}},
            "right": {"set": ["established", "related"]},
        }
    }


def _iifname(name: str) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": name}}


def _accept() -> _Command:
    return {"accept": None}
