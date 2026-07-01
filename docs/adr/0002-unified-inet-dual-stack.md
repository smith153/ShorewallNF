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
- Details still open (how a rule scopes to a single family; exactly how zones type across
  families) are worked out in the Architecture epic.

## Alternatives considered

- **Preserve the split** (separate `shorewallnf`/`shorewallnf6` trees) — familiar and a trivial
  1:1 port of existing configs, but discards the `inet` advantage and doubles config
  maintenance forever. Rejected.
- **IPv4-only MVP, defer the decision** — considered, but the project chose to commit to the
  unified direction now so no work is thrown away, and to ship dual-stack in the MVP.
