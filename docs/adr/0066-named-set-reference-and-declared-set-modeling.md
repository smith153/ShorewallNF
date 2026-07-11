# ADR-0066: Named-set reference & declared-set modeling

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

Real Shorewall configs match traffic against **named sets** (ipsets / nftables named sets): a
`SOURCE`/`DEST` column can carry `+setname` to mean "any host in this set" instead of a literal
address or CIDR. ShorewallNF has no set concept today — `SOURCE`/`DEST` are stored verbatim as
`str` on `Rule`/`Nat`/`MangleRule`, and the generator splits `zone:host` later. A set also has a
family (v4/v6/both) and an element type (host address, or address+port), which the generator must
know to emit a correctly-typed nft `set` object.

Epic #401 scopes named-set support as a diamond rooted at this task (#417): decide **how a set
reference is modeled in the IR** and **how declared sets are known to the compiler**, and build
that IR substrate. The `+setname` token parsing and rule attachment (#418), and the generator
match/emission (#419), are siblings that build against the shape fixed here. Set *population* at
runtime — filling a set with members — is the blacklist epic (#402), out of scope here.

Forces:

- The IR is nftables-agnostic, immutable, and family-aware
  ([ADR-0001](0001-ir-modeling.md), [ADR-0002](0002-unified-inet-dual-stack.md)): a set
  reference and a set declaration are IR data, family-scoped so one config yields family-correct
  `inet` output.
- A compiler that emits wrong rules is worse than one that refuses to run
  ([ADR-0004](0004-error-handling.md)): a malformed set declaration must fail fast, located.
- Two precedents already exist and should be reused rather than reinvented. `Ruleset.actions`
  (#182) is a name-keyed `Mapping` registry of site-declared objects. `HelperDef` /
  `BUILTIN_HELPERS` ([ADR-0040](0040-conntrack-helper-ir-and-registry.md)) is a typed, family-aware
  declared-object record. The generator's `_ct_helper_object` (ADR-0041) shows the shape of a
  self-contained, named nft object emitted once per table.
- Rule compilation ([ADR-0007](0007-rules-compilation.md)) turns a `SOURCE`/`DEST` host term into
  an nft address match; a set reference must slot in there as an alternative host term, not be
  confused with a literal.

## Decision

1. **A set reference is a typed `SetRef(name, negated, family)` host term, distinct from a literal
   CIDR.** Frozen and slotted (ADR-0001), family-aware (ADR-0002, default `BOTH`). It models a
   `+setname` token — with `negated` capturing a leading `!` (`!+setname`) — so the generator emits
   an nft **set-membership** match (`@setname`) rather than an address match. Keeping it a distinct
   type, rather than leaving the `+setname` string verbatim on `source`/`dest`, means the
   type system tells a set reference apart from an address and the generator never re-parses the
   token. `SetRef` is defined by this task; **attaching it onto rules is #418** (this task does not
   widen `Rule`/`Nat`/`MangleRule` or touch `source`/`dest`).

2. **Declared sets live in a `sets` file parsed into a name-keyed `Ruleset.sets` registry**,
   mirroring `Ruleset.actions`. Each row is `<name> <family> <type>`, parsed into a frozen
   `SetDef(name, family, set_type)`: `family` is one of `ipv4`/`ipv6`/`both` (the `Family` enum
   values, ADR-0002) and `type` one of `address`/`address:port` (a `SetType` enum). `Ruleset.sets`
   is `Mapping[str, SetDef]`, defaulting empty so every existing construction is unchanged. A v4
   set and a v6 set produce two registry entries with the correct family/type. The `sets` filename
   is added to the reader's `KNOWN_CONFIG_FILES` so it is discovered in the config dir.

3. **A malformed set declaration fails fast with one located `ConfigError`** (ADR-0004): an unknown
   type, an unknown/missing family, a missing name/type, or a duplicate set name stops the compile
   with the offending `file:line`, rather than being coerced or silently dropped.

4. **The generator will emit a self-contained, empty nft `set` object** (mirroring
   `_ct_helper_object`), which the blacklist epic (#402) later populates — **not** an
   externally-managed set the compiler only references. This fixes the direction; the emission
   itself is a later task (#419/#402), so **this task makes no generator changes** and the existing
   golden/netns suites stay green.

## Consequences

- The IR gains `SetType`, `SetDef`, and `SetRef` now (next to `ZoneMember`/`HelperDef`), plus an
  empty-default `sets: Mapping[str, SetDef]` on `Ruleset`. The parser gains `parse_sets` and the
  reader discovers the `sets` file. No `Rule`/`Nat`/`MangleRule` change and no generator change in
  this task.
- #418 parses `+setname`/`!+setname` tokens into `SetRef` and attaches them to the rule host
  terms; #419 emits the set-membership match and the empty set object; #402 populates sets at
  runtime. Each builds against the shapes fixed here without revisiting the decision.
- Because a set is declared with an explicit family, the generator can derive the nft element type
  (`ipv4_addr`/`ipv6_addr`, optionally `. inet_service`) deterministically, keeping output
  golden-testable.

## Alternatives considered

- **Keep `+setname` verbatim on `source`/`dest` as a `str`.** Rejected: it forces the generator to
  re-parse a token whose meaning (set vs. literal) is already known at parse time, and loses the
  type-level distinction — exactly the confusion ADR-0007's host-term handling would have to guard
  against on every rule.
- **Infer sets implicitly from their references (no `sets` file).** Rejected: family and element
  type cannot be inferred from a bare `+setname`, and the generator needs both to emit a typed nft
  set. An explicit declaration is the single source of truth (mirrors why actions are declared).
- **Reference an externally-managed set instead of emitting one.** Rejected as the default: the
  blacklist epic (#402) needs the compiler to own the set object's lifecycle so a scoped atomic
  replace (ADR-0010) stays self-contained; a self-contained empty set is the right seam.
- **Model `type` as a free `str`.** Rejected: a closed `SetType` enum makes the unknown-type check
  a membership test and documents the two supported kinds, consistent with the IR's typed style.
