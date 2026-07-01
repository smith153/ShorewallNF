# ADR-0001: IR modeling — dataclasses vs pydantic

- **Status:** Accepted
- **Date:** 2026-07-01

## Context

The intermediate representation (IR) is the typed, nftables-agnostic model between the Parser
and the Generator (see [ARCHITECTURE.md](../ARCHITECTURE.md)). How we build those types affects
the dependency footprint, immutability, where validation lives, and mypy support.

Two main options:

- **`dataclasses` (stdlib):** zero runtime dependency; `frozen=True` gives immutability;
  first-class `mypy --strict` support. Raw config values are validated by the Parser, not by
  the model.
- **`pydantic`:** rich runtime validation and coercion with clear errors — at the cost of a
  real runtime dependency.

## Decision

Use **frozen stdlib `dataclasses`** (with `slots=True`) for the IR. The IR is plain, immutable,
nftables-agnostic data; transformations create new instances. Validation of untrusted input
(config files) lives in the Parser/Validator, not in the IR types.

This follows directly from:

- **Minimal dependencies** ([CLAUDE.md](../../CLAUDE.md)) — no runtime PyPI dependency for the
  internal model.
- **Functional core** ([ADR-0003](0003-design-approach.md)) — frozen data flowing through pure
  functions.
- `mypy --strict`, which supports dataclasses natively.

A minimal stub (`src/shorewallnf/ir.py`: `Family`, `Zone`, `Ruleset`) establishes the pattern;
the full IR is built by later tasks.

## Consequences

- **Easier:** trivial construction and testing; immutability by default; nothing to vet or pin.
- **Trade-off:** no coercion/validation on construction — which is intended here. Config errors
  should surface in the Parser with file/line context (see the error-handling ADR, task #11),
  not deep in model constructors. If a future external interface needs schema-style validation,
  revisit *for that interface* rather than adopting pydantic project-wide.

## Alternatives considered

- **pydantic** — its main value is validating/coercing untrusted external input; ours is config
  files handled by our own Parser, so that value belongs there. Adopting it for the internal IR
  would add a runtime dependency for little gain. Rejected.
- **attrs / msgspec** — similar ergonomics to dataclasses but still a dependency, with no
  advantage that justifies it here. Rejected.
