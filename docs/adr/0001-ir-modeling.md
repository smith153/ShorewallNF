# ADR-0001: IR modeling — dataclasses vs pydantic

- **Status:** Proposed (deferred to the Architecture epic)
- **Date:** 2026-06-30

## Context

The intermediate representation (IR) is the typed, nftables-agnostic model that sits between
the Parser and the Generator (see [ARCHITECTURE.md](../ARCHITECTURE.md)). How we build those
types matters: it affects validation ergonomics, error messages, dependency footprint, and how
consistently AI agents can produce and extend the model.

Two main options:

- **`dataclasses` (stdlib)** — zero runtime dependency, fast, simple. Validation and parsing of
  raw config values into typed fields is hand-rolled. Fits the "minimal deps" principle.
- **`pydantic`** — rich validation, coercion, and clear error messages out of the box, at the
  cost of a real runtime dependency and some magic.

## Decision

**Deferred.** This is decided as part of the Architecture epic (MVP epic #0), once there is a
concrete first slice of the IR to evaluate against. Recorded here so the question is not lost.

## Consequences

Until decided, no IR code should assume either approach. The choice should weigh the project's
minimal-dependency stance (favoring `dataclasses`) against validation ergonomics for
agent-written code (favoring `pydantic`).

## Alternatives considered

`attrs` (similar trade-offs to `dataclasses` with more features but still a dependency);
`msgspec` (fast, but less familiar). Both are in scope for the epic to weigh if desired.
