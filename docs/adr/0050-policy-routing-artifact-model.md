# ADR-0050: Policy-routing artifact model — the second output channel

- **Status:** Accepted
- **Date:** 2026-07-03

## Context

The `providers` file ([epic #204](../../README.md), [ADR-0001](0001-ir-modeling.md) `Provider` IR)
describes policy routing: a packet carrying a provider's fwmark is routed out that provider's
interface via its gateway. That decision is made by the **Linux routing subsystem**, not
nftables: an `ip rule` matches the fwmark and selects a per-provider **routing table**, whose
default route names the gateway and egress interface. nftables only *carries* the mark
(`meta mark`); it does not route.

So the Generator, until now a pure `IR → nftables JSON` function
([module-layout](../module-layout.md), [ADR-0003](0003-design-approach.md)), needs a **second
output channel** for the routing artifacts, distinct from the nftables JSON. This ADR fixes how
those artifacts are represented, their family scoping, and the boundary with nft mark handling.

Forces:

- **Pure functional core** ([ADR-0003](0003-design-approach.md)): generation stays a pure
  `IR → data` function with no I/O. Applying the artifacts (running `ip rule`/`ip route`) is the
  Applier's job (#235), not this stage's — so the artifacts must be inert data, not side effects
  or pre-rendered shell strings.
- **Family-aware** ([ADR-0002](0002-unified-inet-dual-stack.md)): a routing table and its default
  route are family-specific — `ip route` needs `-4` or `-6`. A provider's family comes from its
  gateway literal; nothing may be emitted cross-family.
- **Fail closed** ([ADR-0004](0004-error-handling.md)): never emit an artifact that can't be a
  concrete routing entry.
- **One owner for the mark.** The mangle epic (#203) sets marks (`MARK`/`CONNMARK`); providers
  *consume* them. Two stages setting marks would be ambiguous.

## Decision

1. **A frozen `RoutingArtifact` dataclass, one per provider** ([ADR-0001](0001-ir-modeling.md),
   in `ir.py` so both the Generator and the Applier share it). It carries the whole lowering of a
   provider into policy routing:
   - `table_id` — the routing-table id (= the provider **number**); its default route is
     `default via <gateway> dev <interface>`.
   - `fwmark` — the mark (= the provider **mark**) whose `ip rule` selects `table_id`.
   - `gateway`, `interface` — the default route's next-hop and egress device.
   - `family` — `IPV4` or `IPV6` (never `BOTH`; see 3).

   The two artifacts the epic calls out — the **routing table** (table id + default route) and the
   **fwmark→table `ip rule`** — are the two facets of this one record, not two separate types
   (YAGNI). The Applier (#235) renders each into `ip -N rule add fwmark <fwmark> table <table_id>`
   and `ip -N route add default via <gateway> dev <interface> table <table_id>`.

2. **`generate_routing(ruleset) -> tuple[RoutingArtifact, ...]`** in `generator.py`, a pure
   function parallel to `generate` (which stays untouched — nft JSON only). It lowers
   `ruleset.providers` in file order. The two channels are produced independently from the same
   validated `Ruleset`; the CLI/Applier orchestrates both (#235).

3. **Family scoping.** `family` is the provider's resolved family: an IPv4 gateway literal yields a
   v4 artifact, an IPv6 literal a v6 artifact. A provider whose gateway is **not** an address
   literal (e.g. `detect`) has family `BOTH` and cannot be lowered to a concrete family-specific
   routing table — apply-time gateway detection is out of scope for this epic — so it **fails
   closed** ([ADR-0004](0004-error-handling.md)) with one actionable error. Nothing is ever
   emitted cross-family.

4. **Providers emit no nft mark rule.** Mark-*setting* is owned entirely by the mangle epic
   (#203); a provider only *consumes* an already-set fwmark via its `ip rule`. A mark set in the
   mangle/prerouting path is visible to the routing decision, so providers need no nft hook. The
   nftables channel (`generate`) is therefore unchanged by providers.

## Alternatives considered

- **Pre-rendered `ip …` command strings instead of a dataclass.** Rejected: it bakes the command
  surface into the pure core, is harder to assert structurally, and duplicates the Applier's job.
- **Two separate types (`RoutingTable` + `RoutingRule`).** Rejected as premature: they are always
  produced together, one-to-one per provider, so one record is simpler (YAGNI); split later if a
  provider ever yields several routes.
- **Emit both v4 and v6 artifacts for a `detect`/dual-stack gateway.** Rejected: the concrete
  next-hop isn't known without apply-time detection (out of scope), so guessing a family would emit
  a route that may not exist. Fail closed instead.
- **Providers set the mark in nft.** Rejected: it collides with the mangle epic (#203). One owner.

## Consequences

- The routing artifacts are inert, testable data; a golden test pins the model. Applying them
  (iproute2) and atomic teardown are the Applier's concern (#235).
- `detect` gateways are unsupported until apply-time detection is designed — an explicit,
  fail-closed boundary rather than a silent half-feature.
- `generator.py` now hosts two channels (`generate`, `generate_routing`); it can split into a
  package later if it grows unwieldy ([module-layout](../module-layout.md)).
