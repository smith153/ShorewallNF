# Architecture

ShorewallNF is a **compiler**: it reads Shorewall-style configuration and emits an nftables
ruleset. The design is a pipeline with an explicit, nftables-agnostic **intermediate
representation (IR)** in the middle.

```
config dir ─► Reader ─► Parser ─► IR / model ─► Validator ─► nft Generator ─► Applier
                          ▲                                         │
             params + ?if/?FORMAT/?SECTION                    nftables JSON
                 preprocessor resolved here                 (python3-nftables)
```

## Design decisions (ADRs)

The load-bearing decisions behind this pipeline live in [`adr/`](adr/):

- [ADR-0001](adr/0001-ir-modeling.md) — the IR is frozen, family-aware stdlib `dataclasses`.
- [ADR-0002](adr/0002-unified-inet-dual-stack.md) — one family-aware IR, unified `inet` output
  (see *Dual-stack*, below).
- [ADR-0003](adr/0003-design-approach.md) — functional core / imperative shell; data and
  registry dispatch over deep class hierarchies.
- [ADR-0004](adr/0004-error-handling.md) — one `ShorewallNFError` family, raised in the core and
  caught once in the CLI shell → clean message, non-zero exit.

Each stage below maps to a concrete module under `src/shorewallnf/` in
[`module-layout.md`](module-layout.md).

## Stages

- **Reader** — locates and loads the files in a configuration directory.
- **Preprocessor** — resolves `params` variable substitution and the Shorewall directives
  `?if/?elsif/?else/?endif`, `?FORMAT`, and `?SECTION` before parsing.
- **Parser** — turns each file into structured, **nftables-agnostic** IR objects. The parser
  knows Shorewall syntax; it knows nothing about nftables.
- **IR / model** — a typed, **family-aware** representation of zones, interfaces, policies,
  rules, and NAT. This is the contract between parsing and generation. (Whether it is built
  from `dataclasses` or `pydantic` is [ADR-0001](adr/0001-ir-modeling.md).)
- **Validator** — semantic checks: unknown zones, bad references, dependency/ordering sanity.
- **Generator** — consumes the IR and emits nftables **JSON** for libnftables. It is
  responsible for all family-correct output (see below).
- **Applier** — validates and loads the ruleset (`nft -c` to check, then apply).

Keeping these stages separate is what makes the system testable: the parser is unit-tested
against the IR, and the generator is golden-file-tested against nftables output, independently.

## Dual-stack: unified `inet`, family-aware IR

nftables' `inet` address family carries IPv4 and IPv6 in one ruleset, so — unlike Shorewall,
which iptables forced into separate `shorewall`/`shorewall6` programs — ShorewallNF uses a
**single, family-aware IR** and emits `inet` output. This decision is recorded in
[ADR-0002](adr/0002-unified-inet-dual-stack.md).

The same user intent is expressed through **different mechanisms per family**, and the
generator is responsible for the translation:

| Concern | IPv4 | IPv6 |
|---|---|---|
| Service exposure | `DNAT` (+ `MASQUERADE`) | plain `ACCEPT` to a global address (no NAT) |
| ICMP | `icmp` | `ipv6-icmp` / `icmpv6` |
| Interface options | `routefilter`, `logmartians` (v4 sysctls) | `forward=1` |
| Rule sections | often implicit | explicit `?SECTION ESTABLISHED/RELATED/INVALID/NEW…` |
| Zones | same names, typed per family | same names, typed per family |

### Family scoping

Family is **data on the IR**, inferred by the Parser and consumed by the Generator (full rules
in [ADR-0002](adr/0002-unified-inet-dual-stack.md#resolution-2026-07-01-family-scoping-and-cross-family-zones)):

- **Rules** carry a `family` of `both` (default), `ipv4`, or `ipv6`. It is inferred from the
  rule's content — an address literal or a family-specific protocol (`icmp` vs `ipv6-icmp`) fixes
  it; NAT is `ipv4` by construction — and defaults to `both` when nothing pins it. A `both` rule
  is emitted once in `inet` with no family guard; a scoped rule gets `meta nfproto ipv4|ipv6`.
  Mixing v4 and v6 literals in one rule is a fail-fast validation error.
- **Zones** share one namespace (`net`, not `net`/`net6`); **family lives on membership**, not on
  the zone. Interface membership is dual by default; a host/CIDR entry contributes only its own
  family. The Generator materializes each zone into per-family nft sets (`@net_ipv4`,
  `@net_ipv6`), since an nftables set holds a single family.

## Testing pyramid

1. **Golden-file snapshots + `nft -c`** — the fast, hermetic base run on every PR (no root):
   assert the generated ruleset matches a checked-in expected file, and that `nft -c` accepts
   it. This is the TDD workhorse.
2. **Network-namespace integration** — a smaller, privileged CI tier: load the ruleset into an
   `ip netns` sandbox and assert packet-path behavior (policy DROP, DNAT, SNAT, dual-stack
   ICMP). This is what proves "functionally equivalent."
3. **Shorewall-corpus comparison (spike)** — a non-blocking research track: compare our output
   against the original Shorewall test corpus via nft↔iptables translation. May only ever
   cover a subset.
