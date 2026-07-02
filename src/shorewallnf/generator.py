"""Generator — the pure IR → nftables JSON stage (ADR-0001/0003).

Consumes the family-aware IR and emits the base ``inet`` skeleton (ADR-0005) followed by the
inter-zone default-policy rules compiled from the ``Policy`` IR (ADR-0006), as
``python3-nftables`` JSON: one ``inet filter`` table, the fail-closed ``input``/``forward``/
``output`` base chains, the always-on stateful + loopback accepts, and then one rule per policy.
It is dual-stack by construction (ADR-0002) and golden-file-testable without an ``nft`` binary.
"""

from __future__ import annotations

from typing import Any

from .errors import ConfigError
from .ir import Policy, Ruleset, Zone

_FAMILY = "inet"
_TABLE = "filter"

# (chain name == hook name, base-chain policy). Input/forward fail closed; output accepts.
_BASE_CHAINS = (("input", "drop"), ("forward", "drop"), ("output", "accept"))

# nft verdict keyword per (uppercase) policy action; the parser guarantees these three.
_VERDICTS = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject"}

_Command = dict[str, Any]


def generate(ruleset: Ruleset) -> dict[str, list[_Command]]:
    """Emit the base skeleton (ADR-0005) then the inter-zone policy rules (ADR-0006)."""
    commands: list[_Command] = [_table()]
    commands += [_chain(name, policy) for name, policy in _BASE_CHAINS]
    commands.append(_rule("input", [_ct_established_related(), _accept()]))
    commands.append(_rule("input", [_ifname("iifname", "lo"), _accept()]))
    commands.append(_rule("forward", [_ct_established_related(), _accept()]))
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
    src_fw = policy.source in firewalls
    dst_fw = policy.dest in firewalls
    # $FW as a source is host output; as a dest, host input; otherwise it is forwarded traffic.
    chain = "output" if src_fw else "input" if dst_fw else "forward"

    expr: list[_Command] = []
    if chain in ("forward", "input") and policy.source != "all" and not src_fw:
        expr.append(_ifname("iifname", _iface_value(policy, policy.source, interfaces)))
    if chain in ("forward", "output") and policy.dest != "all" and not dst_fw:
        expr.append(_ifname("oifname", _iface_value(policy, policy.dest, interfaces)))
    if policy.log_level:
        expr.append(_log(policy.log_level))
    expr.append(_verdict(policy.action))
    return _rule(chain, expr)


def _iface_value(
    policy: Policy, zone: str, interfaces: dict[str, tuple[str, ...]]
) -> str | dict[str, Any]:
    """A single interface name, or an anonymous set when the zone spans several."""
    names = interfaces.get(zone, ())
    if not names:
        raise ConfigError(
            f"policy {policy.source!r} {policy.dest!r}: "
            f"zone {zone!r} has no interfaces to match on"
        )
    return names[0] if len(names) == 1 else {"set": list(names)}


def _log(level: str) -> _Command:
    return {"log": {"level": level}}


def _verdict(action: str) -> _Command:
    return {_VERDICTS[action]: None}


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


def _ifname(key: str, value: str | dict[str, Any]) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": value}}


def _accept() -> _Command:
    return {"accept": None}
