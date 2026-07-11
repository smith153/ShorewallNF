"""Renderer — pure nft-JSON -> readable text (task #410, ADR-0065).

The read half of the operational-visibility path: it consumes the JSON emitted by
``nft --json list ruleset`` (queried in the applier shell, :func:`shorewallnf.applier.list_ruleset`)
and renders the **Option B annotated columnar** format ADR-0065 fixes as the convention every
``show`` verb follows — a curated, grouped-by-chain report with human ``TARGET`` labels and
``any`` placeholders, not a mirror of ``nft list`` output.

This module is pure (no I/O, no ``nft``), so it is golden-tested against committed fixture JSON
without root (ADR-0003 functional core). ``show rules`` is its first consumer; the siblings
(#411-#415) render other objects through this same convention.
"""

from __future__ import annotations

from typing import Any

from .errors import ConfigError

#: The nftables family every ShorewallNF-owned table lives in (ADR-0002 unified dual-stack).
_FAMILY = "inet"

#: nft verdict keys mapped to their human ``TARGET`` label. A ``jump``/``goto`` carries a target
#: chain name and is rendered separately; anything unlisted falls back to its upper-cased key.
_VERDICT_LABEL = {
    "accept": "ACCEPT",
    "drop": "DROP",
    "reject": "REJECT",
    "return": "RETURN",
    "queue": "QUEUE",
    "dnat": "DNAT",
    "snat": "SNAT",
    "masquerade": "MASQUERADE",
    "redirect": "REDIRECT",
}

_COLUMNS = ("NUM", "TARGET", "PROTO", "SOURCE", "DESTINATION", "DETAIL")


def render_rules(
    ruleset: dict[str, Any], *, table: str, chains: tuple[str, ...] | None = None
) -> str:
    """Render the ``inet`` ``table``'s chains from ``nft -j list`` JSON as annotated columns.

    ``chains`` (when given) scopes output to those chains, in the requested order; otherwise every
    chain in the table is shown, in nft's listing order. A requested chain absent from a **present**
    table is a fail-fast :class:`~shorewallnf.errors.ConfigError` (a typo, ADR-0004); when the table
    itself is absent — the firewall is stopped or cleared — output degrades to an empty-but-valid
    section rather than raising (there is nothing to validate a name against).
    """
    objects = ruleset.get("nftables", [])
    present_chains = _chains_in_table(objects, table)
    rules_by_chain = _rules_by_chain(objects, table)

    if not present_chains:  # firewall stopped/cleared, or an unpopulated table
        return f"Table: {_FAMILY} {table}\n\n  (no chains — firewall stopped or cleared)\n"

    selected = _select_chains(present_chains, chains, table)
    sections = [f"Table: {_FAMILY} {table}", ""]
    for chain in selected:
        sections.append(_render_chain(chain, rules_by_chain.get(chain["name"], [])))
    return "\n".join(sections).rstrip() + "\n"


def _chains_in_table(objects: list[dict[str, Any]], table: str) -> list[dict[str, Any]]:
    return [
        obj["chain"]
        for obj in objects
        if "chain" in obj
        and obj["chain"].get("family") == _FAMILY
        and obj["chain"].get("table") == table
    ]


def _rules_by_chain(
    objects: list[dict[str, Any]], table: str
) -> dict[str, list[dict[str, Any]]]:
    by_chain: dict[str, list[dict[str, Any]]] = {}
    for obj in objects:
        rule = obj.get("rule")
        if rule and rule.get("family") == _FAMILY and rule.get("table") == table:
            by_chain.setdefault(rule["chain"], []).append(rule)
    return by_chain


def _select_chains(
    present: list[dict[str, Any]], chains: tuple[str, ...] | None, table: str
) -> list[dict[str, Any]]:
    if chains is None:
        return present
    by_name = {chain["name"]: chain for chain in present}
    selected = []
    for name in chains:
        if name not in by_name:
            raise ConfigError(f"no chain '{name}' in table {_FAMILY} {table}")
        selected.append(by_name[name])
    return selected


def _render_chain(chain: dict[str, Any], rules: list[dict[str, Any]]) -> str:
    lines = [_chain_header(chain)]
    if not rules:
        lines.append("  (no rules)")
        return "\n".join(lines) + "\n"
    rows = [_rule_row(num, rule) for num, rule in enumerate(rules, start=1)]
    widths = [
        max(len(label), *(len(row[i]) for row in rows))
        for i, label in enumerate(_COLUMNS)
    ]
    lines.append(_format_row(_COLUMNS, widths))
    lines.extend(_format_row(row, widths) for row in rows)
    return "\n".join(lines) + "\n"


def _chain_header(chain: dict[str, Any]) -> str:
    policy = chain.get("policy")
    suffix = f" (policy {policy})" if policy else ""
    return f"Chain {chain['name']}{suffix}"


def _format_row(cells: tuple[str, ...], widths: list[int]) -> str:
    num, rest = cells[0], cells[1:]
    parts = [num.rjust(widths[0])]
    parts.extend(cell.ljust(widths[i + 1]) for i, cell in enumerate(rest))
    return ("  " + "  ".join(parts)).rstrip()


def _rule_row(num: int, rule: dict[str, Any]) -> tuple[str, ...]:
    target = "-"
    proto = "all"
    source = "any"
    dest = "any"
    detail: list[str] = []
    for expr in rule.get("expr", []):
        if "match" in expr:
            proto, source, dest = _apply_match(expr["match"], proto, source, dest, detail)
        else:
            verdict = _verdict(expr)
            if verdict is not None:
                target, extra = verdict
                detail.extend(extra)
    return (str(num), target, proto, source, dest, " ".join(detail))


def _apply_match(
    match: dict[str, Any], proto: str, source: str, dest: str, detail: list[str]
) -> tuple[str, str, str]:
    """Fold one ``match`` expression into the row columns; append leftovers to ``detail``."""
    left = match.get("left", {})
    right = _value(match.get("right"))
    prefix = "!= " if match.get("op") == "!=" else ""
    if "payload" in left:
        field = left["payload"].get("field")
        payload_proto = left["payload"].get("protocol")
        if field == "saddr":
            return proto, prefix + right, dest
        if field == "daddr":
            return proto, source, prefix + right
        if field in ("dport", "sport"):
            new_proto = proto if proto != "all" else str(payload_proto)
            detail.append(f"{field} {prefix}{right}")
            return new_proto, source, dest
        detail.append(f"{payload_proto} {field} {prefix}{right}")
        return (str(payload_proto) if proto == "all" else proto), source, dest
    if "meta" in left:
        key = left["meta"].get("key")
        label = {"iifname": "in", "oifname": "out"}.get(key, key)
        if key in ("l4proto", "nfproto"):
            return (right if proto == "all" else proto), source, dest
        detail.append(f"{label} {prefix}{right}")
        return proto, source, dest
    if "ct" in left:
        detail.append(f"ct {left['ct'].get('key')} {prefix}{right}")
        return proto, source, dest
    detail.append(f"{prefix}{right}")
    return proto, source, dest


def _verdict(expr: dict[str, Any]) -> tuple[str, list[str]] | None:
    """The ``(TARGET, detail-tokens)`` for a verdict/statement, or ``None`` to ignore it."""
    for key in ("jump", "goto"):
        if key in expr:
            return expr[key].get("target", key.upper()), [f"[{key}]"]
    for key, label in _VERDICT_LABEL.items():
        if key in expr:
            return label, _verdict_detail(key, expr[key])
    # counter/log/comment and other non-terminal statements carry no column of their own.
    return None


def _verdict_detail(key: str, body: Any) -> list[str]:
    if key in ("dnat", "snat", "redirect") and isinstance(body, dict):
        addr = body.get("addr")
        port = body.get("port")
        if addr is not None and port is not None:
            return [f"to {addr}:{port}"]
        if addr is not None:
            return [f"to {addr}"]
        if port is not None:
            return [f"to :{port}"]
    return []


def _value(right: Any) -> str:
    """Render an nft match right-hand value compactly (address, set, range, prefix, scalar)."""
    if isinstance(right, dict):
        if "prefix" in right:
            return f"{right['prefix']['addr']}/{right['prefix']['len']}"
        if "set" in right:
            return "{" + ",".join(_value(item) for item in right["set"]) + "}"
        if "range" in right:
            lo, hi = right["range"]
            return f"{_value(lo)}-{_value(hi)}"
    if isinstance(right, list):
        return "{" + ",".join(_value(item) for item in right) + "}"
    return str(right)
