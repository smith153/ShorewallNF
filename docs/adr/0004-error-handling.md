# ADR-0004: Error-handling conventions

- **Status:** Accepted
- **Date:** 2026-07-01

## Context

[ADR-0003](0003-design-approach.md) committed to "fail fast, exit gracefully" — a small
exception family carrying file/line context, raised in the core and caught **once** in the CLI
shell — and deferred the detail to this ADR (task #11).

The forces:

- The core is pure functions over immutable data; side effects (I/O, `nft`, exiting) live only
  in a thin CLI shell (ADR-0003). Error *reporting* is a side effect and belongs at that edge.
- Config is untrusted, multi-file user input. A useful error must point at the **file and line**
  that is wrong, not just describe the symptom.
- Per [CLAUDE.md](../../CLAUDE.md): a compiler that emits wrong firewall rules is worse than one
  that refuses to run. Validate up front, stop with one clear, actionable error — don't scatter
  defensive `if`s trying to survive a bad state.

## Decision

1. **One base:** `ShorewallNFError(Exception)`. Everything the tool raises *deliberately*
   derives from it. The CLI shell catches exactly this type — never broader.
2. **`ConfigError(ShorewallNFError)`** is the workhorse: the user's configuration is invalid. It
   carries structured source location — `path: str | None`, `line: int | None`, `col: int | None`
   — and renders as `path:line:col: message` (omitting parts that are unknown). Location is
   structured, not baked into the string, so the shell formats uniformly and tests can assert.
3. **Stage subclasses grow as needed.** `ParseError` (malformed syntax) and `ValidationError`
   (parses but semantically wrong, e.g. unknown zone) derive from `ConfigError` and are added
   **when their stage is built**, not before (YAGNI). They exist only to let a caller or test
   distinguish failure kinds when a real need appears.
4. **Bugs are not modeled.** Programming errors raise ordinary exceptions (`AssertionError`,
   `KeyError`, …) and are **not** caught — they crash with a traceback, signalling a compiler
   defect to fix, not a user error to explain.
5. **Raise in the core, catch once in the shell.** Core functions signal failure by raising and
   stay pure; there is no `try`/`except` in the core, no `Result`/`Either` threaded through
   returns, no error codes. The CLI `main` wraps the core call in a single
   `except ShorewallNFError`, prints `error: <message>` to stderr, and returns a non-zero code.
6. **Fail fast:** the core stops at the first `ConfigError`. Collecting *all* errors before
   exiting is a possible later enhancement at the shell — deferred, not adopted (YAGNI).
7. **Exit codes:** config error → `1`; CLI usage errors → argparse's own `2`; an uncaught
   exception (a bug) → Python's default. Minimal and conventional.

Illustratively:

```python
# core (pure) — raises, never catches
raise ConfigError("unknown zone 'dmz'", path="rules", line=12)

# shell (main) — the one catch point
try:
    ruleset = compile_config(config_dir)
except ShorewallNFError as err:
    print(f"error: {err}", file=sys.stderr)
    return 1
```

## Consequences

- **Easier:** one place formats user-facing errors; core functions stay pure and testable by
  asserting on exception type + rendered message; agents have a single, uniform pattern.
- **Trade-off:** fail-fast surfaces one error per run, so a user fixes them iteratively. Accepted
  for the MVP; collect-all-errors can be added later at the shell without changing any core
  contract. Bugs deliberately show tracebacks rather than polished messages — correct for a tool
  whose wrong output is dangerous.
- **Follow-up:** the CLI-scaffolding epic (#4) implements `main`'s single catch + exit codes; the
  parsing/validation epics add the `ConfigError` subclasses and populate `path`/`line`; task #13
  wires this convention into ARCHITECTURE.md/CLAUDE.md.

## Alternatives considered

- **`Result`/`Either` threaded through the core** — explicit, but verbose, noisy for agent-written
  code, and unidiomatic in Python. Rejected (consistent with ADR-0003).
- **Broad or per-stage defensive `try`/`except`** — hides bugs and invites survive-anything code
  that violates fail-fast. Rejected.
- **A deep exception hierarchy up front** (per directive/rule kind) — speculative; grow it when a
  stage actually needs to distinguish. Rejected (YAGNI).
- **Collect all config errors before exiting** — better UX, more machinery. Deferred, not
  rejected: reconsider when the parser can meaningfully resynchronise after an error.
