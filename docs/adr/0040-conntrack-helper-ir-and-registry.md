# ADR-0040: Conntrack helper IR model + built-in registry + capability-flag surface

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

Real Shorewall configs attach **conntrack helpers** (FTP, SIP, TFTP, PPTP, IRC, H.323, …) to
flows via the `conntrack` file, so protocols that open secondary data connections (FTP data,
RTP media, the GRE tunnel of PPTP) are tracked as `RELATED`. Each helper has a canonical L4
protocol and default port, and a **family capability**: some kernel helpers are IPv4-only,
others handle both families. Shorewall gates helper loading on `AUTOHELPERS` / `__*_HELPER`
booleans reflecting what the running kernel provides.

Epic #200 scopes conntrack-helper support across the pipeline as a diamond: this task (#219)
is the shared IR root, with parse (#220) and generate (#221) as siblings. This ADR fixes the
IR shapes and the registry/capability boundary they build against — IR modeling only; no
parsing or generation here.

Forces:

- The IR is nftables-agnostic, immutable, family-aware ([ADR-0001](0001-ir-modeling.md),
  [ADR-0002](0002-unified-inet-dual-stack.md)). A helper assignment and a helper's family
  capability are IR data, not nftables concepts, and must be family-correct for `inet` output.
- The core is pure functions over immutable data ([ADR-0003](0003-design-approach.md)); a
  compiler that emits wrong rules is worse than one that refuses to run
  ([ADR-0004](0004-error-handling.md)), so an unknown helper name must be detectable.
- The built-in macro registry (#181, [ADR-0020](0020-macro-and-action-resolution.md)) already
  set the precedent: a static, documented, name-keyed data table of built-ins, separate from
  the config the parser builds. Conntrack helpers reuse that shape.
- Module autodetection (probing the running kernel for loaded helpers) is apply-time I/O and is
  **out of scope** per the epic; the platform-capability input must be modeled as pure data.

## Decision

1. **A family-aware `ConntrackHelper` IR type is the config-side assignment.** Frozen, slotted
   (ADR-0001), it carries the canonical helper `name` plus the flow-scope narrowing from the
   `conntrack` row — `source`/`dest` (raw `zone` / `zone:host` tokens) and `proto`/`dport`,
   verbatim — and the resolved `family` (default `BOTH`, narrowed to `IPV4` for a v4-only helper
   or a v4-literal row). It is added to `Ruleset` as an immutable
   `conntrack_helpers: tuple[ConntrackHelper, ...] = ()` field, consistent with the other
   collections. The parser (#220) populates it; this stage only fixes the shape.

2. **A static built-in registry maps helper name → capability, as pure data.** A frozen
   `HelperDef` (name, L4 `proto`, default `ports`, and `family_capability`) describes one
   built-in helper; the name-keyed, read-only `BUILTIN_HELPERS` mapping in
   `shorewallnf/conntrack.py` holds the documented subset (cf. `macros.BUILTIN_MACROS`). Only
   the helpers the reference config needs are listed (YAGNI); the mapping is enumerable, so an
   unknown name is detectable by the parser/validator without this module doing any lookup.

3. **Family capability is `Family.IPV4` (v4-only) or `Family.BOTH` (v6-capable) — never
   `IPV6`.** A helper the kernel supports on both families is `BOTH`; one with no IPv6 conntrack
   support is `IPV4`. There is no v6-only helper, so `Family.IPV6` is not a valid capability
   value (asserted in tests). This is the widest family a helper *can* scope to; a specific
   `ConntrackHelper` assignment may narrow further via a v4 literal.

4. **The compile-time capability-flag surface is a pure-data `HelperCapabilities`.** It models
   the `AUTOHELPERS` / `__*_HELPER` input as a frozen set of helper names the platform provides,
   with a `provides(name)` query. It is pure data with no I/O — module autodetection is out of
   scope — and is the surface the generator (#221) consults to gate emission of a helper's rules.

## Consequences

- The IR gains `ConntrackHelper`, `HelperDef`, and `HelperCapabilities` now (this task), plus a
  new `conntrack_helpers` tuple on `Ruleset`. `conntrack.py` (registry data) lands alongside
  `macros.py` as a cross-cutting built-in registry.
- The parser (#220) reads the `conntrack` file into `ConntrackHelper` values, resolving names
  against `BUILTIN_HELPERS` and inferring family from the entry's capability and the row's
  literals. The generator (#221) consumes `conntrack_helpers` and `HelperCapabilities` to emit
  family-correct `RELATED`-tracking rules, skipping helpers the platform does not provide.
- Because capability is compile-time data, the same config compiles deterministically and is
  golden-testable; there is no apply-time kernel probing to mock.

## Alternatives considered

- **Fold the helper's proto/port into `ConntrackHelper` instead of a registry.** Rejected: the
  canonical proto/port is a property of the *helper*, not of each assignment; duplicating it on
  every row invites drift and loses the single enumerable source of truth (mirrors why macros
  use a registry).
- **Model family capability as a `bool` (`v6_capable`).** Rejected: the IR already speaks
  `Family` (ADR-0002); reusing it keeps one family vocabulary and reads directly as the widest
  scope, at the cost of excluding the impossible `IPV6` value (guarded by test).
- **Detect available helpers by probing the kernel.** Rejected here as out-of-scope apply-time
  I/O; the capability surface is pure compile-time data so the core stays a pure function.
