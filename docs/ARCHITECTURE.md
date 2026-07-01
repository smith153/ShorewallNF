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
