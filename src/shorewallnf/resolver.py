"""Resolver — expand macro/action call sites into verdict rules (ADR-0020, #184).

The pure IR→IR stage between Parser and Validator: Reader → Parser → IR → **Resolver** →
Validator → Generator. It replaces each :class:`~shorewallnf.ir.Rule` whose ``action`` names a
:class:`~shorewallnf.ir.MacroDef` in scope with one rule per body row, in body order, narrowing
each expanded rule by the call site. After resolution the ruleset holds only built-in-verdict
rules, so the validator and generator stay macro-unaware (ADR-0020 §3).

Registry lookup combines the built-in :data:`~shorewallnf.macros.BUILTIN_MACROS` (#181) with the
site-defined :attr:`~shorewallnf.ir.Ruleset.actions` (#182); a site definition overrides a
built-in of the same name (ADR-0020 §6, site wins). An action that is neither a built-in verdict
nor a ``MacroDef`` in scope, or a narrowing whose per-field intersection is empty, fails fast with
a :class:`~shorewallnf.errors.ConfigError` (ADR-0004) that cites the call site's ``path:line`` when
known (#195) and identifies the rule by content.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from .errors import ConfigError
from .ir import Family, MacroDef, MacroRule, Rule, Ruleset
from .macros import BUILTIN_MACROS

_VERDICTS = frozenset({"ACCEPT", "DROP", "REJECT"})


def resolve(ruleset: Ruleset) -> Ruleset:
    """Expand every macro/action-invoking rule into its narrowed verdict rules (ADR-0020).

    Returns the ruleset with its ``rules`` replaced by the expansion; verdict rules pass through
    unchanged. Raises :class:`ConfigError` on the first unknown action or empty narrowing.
    """
    # Site actions override built-ins of the same name (ADR-0020 §6): later keys win.
    registry: Mapping[str, MacroDef] = {**BUILTIN_MACROS, **ruleset.actions}
    expanded: list[Rule] = []
    for rule in ruleset.rules:
        macro = registry.get(rule.action)
        if macro is None:
            if rule.action not in _VERDICTS:
                raise ConfigError(
                    f"unknown action {rule.action!r}: not a built-in verdict "
                    f"(ACCEPT/DROP/REJECT) or a macro/action in scope ({_describe(rule)})",
                    path=rule.path,
                    line=rule.line,
                )
            expanded.append(rule)
            continue
        expanded.extend(_expand(rule, body_row) for body_row in macro.body)
    return replace(ruleset, rules=tuple(expanded))


def _expand(rule: Rule, body: MacroRule) -> Rule:
    """One expanded rule: the body's verdict, the call site's source/dest/section, and each of
    proto/dport/sport/family narrowed to the intersection of call site and body row."""
    return Rule(
        action=body.action,
        source=rule.source,
        dest=rule.dest,
        proto=_narrow(rule, body, "proto", rule.proto, body.proto),
        dport=_narrow(rule, body, "dport", rule.dport, body.dport),
        sport=_narrow(rule, body, "sport", rule.sport, body.sport),
        section=rule.section,
        family=_narrow_family(rule, body),
        path=rule.path,
        line=rule.line,
    )


def _narrow(
    rule: Rule, body: MacroRule, field: str, call: str | None, row: str | None
) -> str | None:
    """Intersect a call-site value with a body-row value: ``None`` yields the other side, equal
    values collapse, disjoint concrete values fail fast (the empty-intersection case, AC2)."""
    if call is None:
        return row
    if row is None:
        return call
    if call == row:
        return call
    raise ConfigError(
        f"macro/action {rule.action!r} expansion is unsatisfiable: call-site {field} {call!r} "
        f"and body {field} {row!r} do not overlap ({_describe(rule)})",
        path=rule.path,
        line=rule.line,
    )


def _narrow_family(rule: Rule, body: MacroRule) -> Family:
    """Intersect the call site's family with the body row's; ``BOTH`` is unconstrained, and two
    disjoint concrete families are an empty intersection (fail fast)."""
    if rule.family is Family.BOTH:
        return body.family
    if body.family is Family.BOTH:
        return rule.family
    if rule.family is body.family:
        return rule.family
    raise ConfigError(
        f"macro/action {rule.action!r} expansion is unsatisfiable: call-site family "
        f"{rule.family.value} and body family {body.family.value} do not overlap "
        f"({_describe(rule)})",
        path=rule.path,
        line=rule.line,
    )


def _describe(rule: Rule) -> str:
    """Identify a rule by its content for an error message (ADR-0020 §5 error-by-content): the
    action name plus the source/dest/proto/dport/sport fields that are set."""
    parts = [f"action={rule.action}", f"source={rule.source}", f"dest={rule.dest}"]
    for label, value in (("proto", rule.proto), ("dport", rule.dport), ("sport", rule.sport)):
        if value is not None:
            parts.append(f"{label}={value}")
    return "rule: " + " ".join(parts)
