# ADR-0020: Macro and custom-action resolution

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

Real Shorewall configs put a **macro** or **custom action** name in the `ACTION` column of the
`rules` file (e.g. `Ping`, a drop-invalid action, or a site-defined `action.<Name>`) instead of
only the built-in `ACCEPT`/`DROP`/`REJECT` verdicts. A macro/action is a *named body* of further
rules; invoking it means emitting that body with the call site's own source/dest/proto/port
applied. Today the generator understands only built-in verdicts (`generator.py`) and the validator
only recognises verdict actions (`validator.py`), so a rule whose action is a macro/action name
cannot compile. Epic #176 scopes the subset whose bodies expand purely to `ACCEPT`/`DROP`/`REJECT`.

Forces:

- The IR is nftables-agnostic, immutable, family-aware ([ADR-0001](0001-ir-modeling.md),
  [ADR-0002](0002-unified-inet-dual-stack.md)). A macro/action definition is IR data, not an
  nftables concept.
- The core is pure functions over immutable data, staged as
  Reader → Parser → IR → Validator → Generator ([ADR-0003](0003-design-approach.md),
  [module-layout.md](../module-layout.md)). Each stage must keep a single concern.
- The parser is purely syntactic (text → IR, one file at a time); resolving a *name* needs a
  registry that spans built-ins plus every parsed `action.<Name>` file — a cross-cutting lookup
  the parser should not carry.
- A compiler that emits wrong rules is worse than one that refuses to run
  ([ADR-0004](0004-error-handling.md)): an unknown/malformed name must fail fast with one clear,
  located error.

## Decision

1. **One IR type for both macros and custom actions.** A definition is a `MacroDef` — a `name`
   plus an ordered `body` of `MacroRule` verdict templates — family-aware per ADR-0002. For the
   scoped subset a Shorewall macro (textual inline expansion) and a custom action (a jumped-to
   chain) both reduce to "a named body of verdict rules", so they share this type. A `MacroRule`
   carries a verdict `action` and optional `proto`/`dport`/`sport` narrowing; source/dest are not
   modeled on it because they come from the invoking rule.

2. **`Rule.action` stays a plain `str`; names are not type-distinguished from verdicts.** A
   macro/action name and a built-in verdict occupy the same `str` field. The compiler tells them
   apart by **lookup**, not by type: an action is a macro/action iff a `MacroDef` of that name is
   in scope, otherwise it must be a built-in verdict. Introducing a distinct type (e.g. a tagged
   `Verdict | MacroCall`) is YAGNI — no stage needs it, and the resolver's lookup is the single
   source of truth.

3. **Expansion runs in a dedicated resolver stage between Parser and Validator:**
   Reader → Parser → IR → **Resolver** → Validator → Generator. The resolver is a pure IR→IR
   transform: it replaces each macro/action-invoking `Rule` with the expanded verdict `Rule`s of
   the named `MacroDef`'s body, in order. The parser stays purely syntactic; the validator and
   generator keep seeing only built-in verdicts and need no macro awareness.

4. **The invoking rule narrows the body.** Each expanded rule inherits the call site's
   source/dest/family; a body line's own `proto`/`dport`/`sport` **intersects** with (further
   narrows), rather than replaces, the invoking rule's — e.g. a rule `ACCEPT net fw` invoking a
   macro line `ACCEPT - tcp 22` yields `ACCEPT net fw tcp 22`. The detailed narrowing rules and
   the wiring into the compile pipeline are the resolver task's (#184) to implement against this
   stage boundary.

5. **Unknown or malformed names fail fast.** An action that is neither a built-in verdict nor a
   `MacroDef` in scope raises a `ConfigError` (ADR-0004) in the resolver, naming the offending
   action and its call site (path/line). Resolution stops at the first such error.

6. **Site-defined definitions override built-ins of the same name.** A parsed `action.<Name>`
   takes precedence over a built-in `MacroDef` of the same name (Shorewall-compatible), rather
   than being a collision error — overriding is well-defined, not an ambiguous state, so it is not
   a fail-fast case. The built-in registry (#181) and site-action parsing (#182) build on this.

## Consequences

- The IR gains `MacroDef`/`MacroRule` now (this task); the resolver stage, built-in registry, and
  site-action parser land as follow-up tasks (#181, #182, #184) against the boundary fixed here.
- Validator and generator are untouched by macros: after resolution the ruleset contains only
  built-in-verdict rules, so all existing verdict-rule behaviour is unchanged.
- Because names are resolved by lookup rather than typed, a typo'd verdict and an unknown macro
  are the same failure — one clear "unknown action" error, consistent with ADR-0004.
- A resolver stage is a new module (`resolver.py`) and a new row in module-layout when #184 lands.

## Alternatives considered

- **Expand at parse time.** Rejected: the parser would need a registry spanning built-ins and all
  `action.<Name>` files while parsing a single file, breaking its one-file, purely-syntactic
  concern and its testability in isolation.
- **Expand in the generator.** Rejected: the validator would then have to understand macro names
  (or skip validating them), and validation should see the final, expanded rules — not names it
  cannot check.
- **Type-distinguish a macro call from a verdict in `Rule.action`** (e.g. a union type). Rejected
  as YAGNI: no stage needs the distinction at the type level; a lookup in the resolver is simpler
  and keeps `Rule` unchanged.
