# ADR-0002: Unified `inet`, family-aware IR, dual-stack

- **Status:** Accepted
- **Date:** 2026-06-30

## Context

Original Shorewall ships two separate programs, `shorewall` (IPv4) and `shorewall6` (IPv6),
with separate configuration trees and separate compiled output. That split exists because
**iptables** required separate `iptables`/`ip6tables` backends.

nftables removes that constraint: the **`inet` address family** carries IPv4 and IPv6 rules in
a single table/ruleset. However, the same user intent is expressed through different mechanisms
per family — IPv4 exposes services via `DNAT`/`MASQUERADE`, while IPv6 does no NAT and uses
direct `ACCEPT` to global addresses; ICMP is `icmp` vs `ipv6-icmp`; interface options and rule
sections differ. (See the reconciliation table in [ARCHITECTURE.md](../ARCHITECTURE.md).)

## Decision

ShorewallNF uses a **single, family-aware IR** and generates **`inet`-family** nftables output.
There is one configuration model, not a v4 tree and a v6 tree. Each address, rule, and
interface option carries or infers its family, and the Generator emits family-correct nftables
for both. The MVP is **dual-stack**.

## Consequences

- **Easier:** one config to author and maintain; the biggest UX win over original Shorewall;
  no v4/v6 split to unwind later.
- **Harder / required work:** the IR must be family-aware from day one; the Generator must
  handle per-family mechanism differences (NAT vs direct-accept, `icmp` vs `ipv6-icmp`, etc.);
  the preprocessor must support `?SECTION`/`?FORMAT` because the v6 rules rely on them.
- The details of how a rule scopes to a single family and how zones type across families are
  resolved below (see [Resolution](#resolution-2026-07-01-family-scoping-and-cross-family-zones)).

## Alternatives considered

- **Preserve the split** (separate `shorewallnf`/`shorewallnf6` trees) — familiar and a trivial
  1:1 port of existing configs, but discards the `inet` advantage and doubles config
  maintenance forever. Rejected.
- **IPv4-only MVP, defer the decision** — considered, but the project chose to commit to the
  unified direction now so no work is thrown away, and to ship dual-stack in the MVP.

## Resolution (2026-07-01): family scoping and cross-family zones

The two details deferred above are settled here (task #9). They fit the family-aware,
dataclass IR ([ADR-0001](0001-ir-modeling.md)) and the functional-core generator
([ADR-0003](0003-design-approach.md)): family is **data on the IR**, inferred by the Parser
and consumed by the Generator.

### How a rule scopes to a single family

Every IR rule carries a `family` of `both` (the default), `ipv4`, or `ipv6`:

- **Inferred from content.** A literal address or CIDR fixes the family (`10.0.0.0/8` → `ipv4`;
  `2001:db8::/32` → `ipv6`), as do family-specific protocols (`icmp` → `ipv4`;
  `ipv6-icmp`/`icmpv6` → `ipv6`). NAT verbs (`DNAT`, `SNAT`, `MASQUERADE`) are `ipv4` by
  construction — IPv6 does no NAT; its equivalent is a direct `ACCEPT`.
- **Default is `both`.** A rule with no family-specific token (e.g. `ACCEPT net fw tcp 22`)
  applies to both families: the Generator emits it once in the `inet` table with no
  `nfproto`/`ip`/`ip6` guard, so it matches v4 and v6 naturally.
- **Explicit scoping** uses the preprocessor conditionals `?if __IPV4 … ?endif` /
  `?if __IPV6 …` (part of the preprocessor epic) for the rare rule an author must force to one
  family without an address literal.
- **Mixing families in one rule is a fail-fast error.** A rule naming both a v4 and a v6 literal
  cannot be a single `inet` rule; the Validator rejects it with a file/line error.

The Generator translates `family` into output: `both` → no guard; `ipv4` → `meta nfproto ipv4`
(or an `ip …` match); `ipv6` → `meta nfproto ipv6` (or an `ip6 …` match).

### How zones type across families

There is **one zone namespace**, not `net`/`net6`. A zone is a single, family-independent
identity; **family lives on its membership**, not on a second zone object:

- **Interface membership is dual by default.** A zone bound to an interface (`net = eth0`)
  covers both the v4 and v6 traffic on that interface.
- **Host/CIDR membership carries the family of its literal.** `net = eth0:10.0.0.0/8`
  contributes IPv4-only membership; `net = eth0:2001:db8::/32` contributes IPv6-only. A zone is
  therefore dual, v4-only, or v6-only as an emergent consequence of how it is populated — the
  IR does not model a separate per-family zone.
- **The Generator materializes membership into per-family nft sets.** Because an nftables set
  holds one family, a zone with mixed members becomes two sets (`@net_ipv4`, `@net_ipv6`) and
  matches emit `ip saddr @net_ipv4` / `ip6 saddr @net_ipv6`. A zone with no v6 members simply
  never matches v6 traffic — no special case needed.

**IR shape (informative):** a `Zone` has a name and a list of membership records, each carrying
`(interface, host?, family)` with `family ∈ {ipv4, ipv6, both}`.
