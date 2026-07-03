# ADR-0041: Conntrack helper compilation — objects, assignment rules, family scoping, gating

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

[ADR-0040](0040-conntrack-helper-ir-and-registry.md) modelled the config-side `ConntrackHelper`
IR, the built-in `HelperDef` registry (canonical proto/port + family capability), and the pure
`HelperCapabilities` surface (the `AUTOHELPERS` / `__*_HELPER` equivalent, as compile-time data).
This ADR is the sibling generate step (#221): how the Generator lowers those entries into the
`inet filter` skeleton ([ADR-0005](0005-nftables-base-chain-layout.md)).

nftables represents an application helper as a **named `ct helper` object** (per-table), bound to
a flow by a rule statement (`ct helper set "<name>"`, non-terminal). The object carries a type, an
L4 protocol, and an **L3 protocol** (`l3proto`); the shipped example
`/usr/share/doc/nftables/examples/ct_helpers.nft` declares helpers in an `inet` table with
`l3proto inet` and assigns them with `tcp dport 21 ct helper set "ftp-standard"`.

Forces:

- **Dual-stack in one `inet` table** ([ADR-0002](0002-unified-inet-dual-stack.md)): one object must
  serve both families where the helper supports both; a v4-only helper must never reach a v6 packet.
- **Fail closed** ([ADR-0004](0004-error-handling.md)): never emit an object/rule the platform would
  reject. An unknown helper name is malformed IR; a helper the kernel lacks must be skipped, not
  emitted (Shorewall's `AUTOHELPERS` gate).
- **Load ordering:** nft applies commands top-to-bottom, so a `ct helper` object must be added
  before any rule references it.
- The Generator is a pure `IR → JSON` function ([ADR-0003](0003-design-approach.md)) and reuses the
  ADR-0006/0007 zone-matching machinery, so helper assignment lands in the family-correct chain
  with the same `iifname`/`oifname`/`zone:host` handling as any rule.

## Decision

1. **One `ct helper` object per distinct helper name, `l3proto` from its capability.** The object is
   `{"add": {"ct helper": {family "inet", table "filter", name, type, protocol, l3proto}}}`, where
   `type` and `name` are the helper's registry name and `protocol` its L4 proto. `l3proto` follows
   the `HelperDef.family_capability`: **`inet`** for a v6-capable helper (one object serving both
   families, per the shipped nft example), **`ip`** for a v4-only helper. Objects are deduplicated
   by name (several rows may share a helper) and emitted **before** the assignment rules.

2. **One `ct helper set` assignment rule per `ConntrackHelper` row, in the flow's base chain.**
   Reusing ADR-0006/0007 zone matching, the rule lands in `input`/`forward`/`output` by the role of
   `$FW` in the row's source/dest, with the matching `iifname`/`oifname` and any `zone:host`
   narrowing. It then matches the helper's canonical proto/default port (from the registry) unless
   the row overrides `proto`/`dport`, and ends with the non-terminal `{"ct helper": "<name>"}`
   statement — the packet falls through to normal filtering. The rules are emitted **before** the
   feature rules and policy defaults so a fall-through verdict cannot shadow the assignment; they
   sit after the ADR-0005 `ct state established,related accept`, so the helper is set on the
   originating (NEW) packet, exactly where conntrack needs it to mark the later data flow RELATED.

3. **Family scoping of a v6-incapable helper (ADR-0002).** The assignment rule carries a
   `meta nfproto` guard derived from the row's resolved `family`: **none** for `BOTH` (dual-stack),
   `meta nfproto ipv4` for `IPV4`, `meta nfproto ipv6` for `IPV6`. A v4-only helper is thus both
   object-scoped (`l3proto ip`) and rule-scoped (`meta nfproto ipv4`); it emits **no v6 path** — no
   v6 object, no `ip6`/`ipv6` rule.

4. **Capability gating (AUTOHELPERS-equivalent), skip-with-warning.** Each row is first resolved
   against the built-in registry; an unknown name is malformed IR and **fails closed**
   ([ADR-0004](0004-error-handling.md)) regardless of the capability surface. A known helper the
   `HelperCapabilities` surface does not `provides()` is **skipped with a `warnings.warn`** and
   emits nothing — no object, no rule — leaving the remaining ruleset well-formed and loadable. The
   surface reaches the generator as a `capabilities` argument defaulting to the empty set, so a
   helper is emitted only when the caller declares the platform provides it (fail-closed default).

## Consequences

- `generate()` gains an optional `capabilities: HelperCapabilities` argument (default empty);
  existing callers are unaffected. A config with `conntrack_helpers` but no declared capabilities
  compiles to the base ruleset plus a warning per helper — deterministic and golden-testable.
- The object-before-rule ordering and per-name dedup keep a single load valid even when one helper
  is bound to several flows.
- Because gating is compile-time data, the golden fixtures (v6-capable, v4-only, skipped) render
  without an `nft` binary; the CI `nft --check` step is the authoritative loadability guarantee.

## Alternatives considered

- **Two objects (`l3proto ip` + `l3proto ip6`) for a v6-capable helper.** Rejected: the shipped nft
  example uses a single `l3proto inet` object in an `inet` table, which is simpler and matches the
  one-object-per-name model; a second object would need a second name and a second rule for no gain.
- **`mangle` statement (`{"mangle": {"key": {"ct": {"key": "helper"}}, ...}}`) for the assignment.**
  Rejected: libnftables documents a dedicated `{"ct helper": EXPRESSION}` statement ("enable the
  specified conntrack helper for this packet"), which is the canonical, clearer form.
- **Emit the object/rule and let the kernel ignore an unavailable helper.** Rejected: nft may reject
  an unknown helper type at load, and Shorewall's `AUTOHELPERS` exists precisely to gate this;
  skip-with-warning keeps the ruleset loadable (fail closed).
- **Probe the running kernel for loaded helpers.** Out of scope per epic #200 and
  [ADR-0040](0040-conntrack-helper-ir-and-registry.md) — capability is pure compile-time data.
