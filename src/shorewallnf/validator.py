"""Validator — semantic checks over the IR, the pure core stage before the Generator.

Validation runs up front (ARCHITECTURE.md) so the compiler fails fast with one clear,
actionable error rather than emitting a ruleset with a dead or misleading rule
(CLAUDE.md: a compiler that emits wrong firewall rules is worse than one that refuses).
It is a pure ``IR -> IR`` function (module-layout.md): it returns the ruleset unchanged
when every check passes, and raises :class:`~shorewallnf.errors.ConfigError` otherwise.

Checks so far:

- **ESTABLISHED/RELATED base-accept shadow (#138).** ADR-0005's base chains accept
  ``ct state {established, related}`` before any feature rule, so a ``DROP``/``REJECT`` in the
  ESTABLISHED or RELATED ``?SECTION`` is unreachable. Reject it; an ``ACCEPT`` there is a
  redundant no-op and is allowed. (A FASTACCEPT-off mode that made the base accept conditional
  is out of scope — a future ADR if a real need for mid-connection policy arrives.)
"""

from __future__ import annotations

from .errors import ConfigError
from .ir import Provider, Rule, Ruleset

# ESTABLISHED/RELATED are accepted by the ADR-0005 base chain before any feature rule; INVALID
# and NEW are not, so a DROP/REJECT there is reachable and unaffected.
_BASE_ACCEPTED_SECTIONS = frozenset({"ESTABLISHED", "RELATED"})
_REJECTING_ACTIONS = frozenset({"DROP", "REJECT"})


def validate(ruleset: Ruleset) -> Ruleset:
    """Run every semantic check over ``ruleset``; return it unchanged, or raise ``ConfigError``."""
    for rule in ruleset.rules:
        _reject_shadowed_section_rule(rule)
    _validate_providers(ruleset.providers, {iface.name for iface in ruleset.interfaces})
    return ruleset


def _validate_providers(
    providers: tuple[Provider, ...], interface_names: set[str]
) -> None:
    """Reject inconsistent ``providers`` definitions (#233, ADR-0004, epic #204).

    Fail fast on a fwmark or routing-table number reused across providers (both must be unique to
    steer traffic deterministically) or an interface naming no configured ``Interface``. Each is a
    single actionable error naming the collision / unknown reference.
    """
    marks: dict[int, str] = {}
    numbers: dict[int, str] = {}
    for provider in providers:
        if provider.mark in marks:
            raise ConfigError(
                f"provider {provider.name!r} reuses fwmark {provider.mark} already assigned to "
                f"provider {marks[provider.mark]!r} — each provider needs a distinct mark"
            )
        marks[provider.mark] = provider.name
        if provider.number in numbers:
            raise ConfigError(
                f"provider {provider.name!r} reuses routing-table number {provider.number} "
                f"already assigned to provider {numbers[provider.number]!r} — each provider needs "
                f"a distinct number"
            )
        numbers[provider.number] = provider.name
        if provider.interface not in interface_names:
            raise ConfigError(
                f"provider {provider.name!r} names unknown interface {provider.interface!r} "
                f"(no such interface is configured)"
            )


def _reject_shadowed_section_rule(rule: Rule) -> None:
    """Fail fast on a ``DROP``/``REJECT`` in an ESTABLISHED/RELATED section (#138, ADR-0005)."""
    section = (rule.section or "").upper()
    if section in _BASE_ACCEPTED_SECTIONS and rule.action in _REJECTING_ACTIONS:
        raise ConfigError(
            f"rule {rule.action} {rule.source!r} {rule.dest!r}: {rule.action} in the "
            f"{section} section is unreachable — established/related traffic is already "
            f"accepted by the base chain (ADR-0005), so this rule is dead. Remove it "
            f"(mid-connection DROP/REJECT is not supported).",
            path=rule.path,
            line=rule.line,
        )
