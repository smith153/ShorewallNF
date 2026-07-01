# ADR-0003: Overall design approach

- **Status:** Accepted
- **Date:** 2026-07-01

## Context

ShorewallNF is a compiler: config in, nftables out, through an IR (see
[ARCHITECTURE.md](../ARCHITECTURE.md)). Epic #3 asks us to pick a coding approach *before*
much code exists, so implementers (human and agent) build consistently. The macro-architecture
(the IR pipeline) is already settled; open is the coding style *inside* it, plus confirming the
Python floor.

Constraints in play: minimal dependencies; `mypy --strict`; golden-file testability; and the
project's [code philosophy](../../CLAUDE.md) (YAGNI, fail-fast, brevity). Much of the code will
be written by AI agents, which rewards a simple, uniform style over clever abstraction.

## Decision

1. **Functional core, imperative shell.** The core — `parse → IR → validate → generate` — is
   pure functions over immutable data: data in, new data out, no I/O, no global state. All side
   effects (reading the config directory, invoking `nft`, exiting) live in a thin CLI shell at
   the edges. This makes golden-file testing trivial and keeps reasoning local.
2. **Data + functions over deep class hierarchies.** The IR is plain data (dataclasses-leaning;
   the exact library is [ADR-0001](0001-ir-modeling.md)). Behaviour that varies by directive or
   rule kind uses **dispatch via a registry** (a dict keyed by type) rather than inheritance
   trees. Reach for a class only when behaviour and state genuinely travel together.
3. **Errors: fail fast, exit gracefully.** A small exception family carrying file/line context,
   raised anywhere in the core and caught **once** in the CLI shell → one clear message →
   non-zero exit. No `Result` monads, no error codes threaded through returns. Detail is
   [ADR — error-handling conventions](../../docs/adr/) (task #11).
4. **Python floor ≥ 3.11**, confirmed. Reflected in `pyproject.toml` (`requires-python`,
   `tool.ruff.target-version`, `tool.mypy.python_version`) and CI, and guarded by
   `tests/test_python_floor.py`.

**Explicitly not doing:** DDD, hexagonal/ports-and-adapters ceremony, DI frameworks, abstract
base classes "for flexibility", or Factory/Strategy/Visitor for their own sake. That is YAGNI
applied to architecture — add structure when a concrete need appears.

## Consequences

- **Easier:** unit-testing the parser against the IR and golden-file-testing the generator, both
  in isolation; predictable, uniform code for agents to extend; fewer moving parts.
- **Accepted trade-off:** contributors expecting an OO framework will find plain functions +
  data instead. Genuinely polymorphic spots (per-file parsers, per-rule generators) use a flat
  registry, which must be discoverable — mitigated by keeping registries in one obvious module
  per stage.
- Downstream ADRs build on this: IR modeling ([#10](../adr/0001-ir-modeling.md)) and error
  handling (#11) refine points 2 and 3.

## Alternatives considered

- **Moderate OOP** — each rule/directive a class with a `.to_nft()` method, generation via
  polymorphism. Familiar, but couples the IR to nftables and scatters generation logic across
  many small classes. Rejected in favour of keeping the IR nftables-agnostic.
- **Defer entirely** — leave the approach unstated and let each PR choose. Rejected: it
  guarantees an inconsistent codebase, which is exactly what this epic exists to prevent.
