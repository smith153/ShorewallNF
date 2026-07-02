# ADR-0009: SNAT/MASQUERADE compilation — postrouting source-NAT rules

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

[ADR-0008](0008-nat-compilation.md) fixed the base `inet nat` skeleton — the table plus the
`prerouting` (dstnat-priority) and `postrouting` (srcnat-priority) base chains, emitted only when
a NAT entry needs the nat table — and compiled a v4 `DNAT` into a prerouting `dnat` rule plus a
matching filter `forward` accept. It deliberately left `postrouting` empty, ready for the source-NAT
sibling. This ADR fixes that sibling: how a `MASQUERADE`/`SNAT` entry from the `snat` file compiles
into a `postrouting` rule.

The `snat` parser (#156) populates the `Nat` IR's source-NAT columns: `source_nets` (the SOURCE
network list, a comma-separated CIDR list preserved verbatim), `out_interface` (the egress
interface), and `snat_to` (the explicit `SNAT(<addr>)` address, `None` for `MASQUERADE`). Unlike a
`DNAT`, a source-NAT entry names no zones — its SOURCE and DEST are literal networks and an
interface — so it needs no zone/interface lookup.

Forces:

- **Source NAT is IPv4-only** ([ADR-0002](0002-unified-inet-dual-stack.md)): IPv6 does no NAT, so
  there is no v6 source-NAT variant at all (an IPv6 host keeps its global address). `family` is
  always `Family.IPV4` for a source-NAT `Nat`.
- **The `postrouting` base chain already exists** (ADR-0008): this task only adds rules to it, and
  the nat table is emitted whenever a source-NAT entry is present because `_needs_nat_table` already
  counts every non-IPv6 NAT entry — a v4 source-NAT included.
- **Reuse the ADR-0007 match structure** — interface match then address narrowing, in that fixed
  order, so output stays deterministic and golden-testable.
- **No new forward path.** A `DNAT` needs a `forward` accept because it redirects a NEW inbound
  connection to an internal host through the fail-closed `forward` chain (ADR-0008). Source NAT only
  rewrites the *source* address of a connection the `forward` policy/rules already admit — it opens
  nothing. Adding a `forward` accept would wrongly widen the policy.
- **Golden-file-testable** without an `nft` binary (epic #77).

## Decision

1. **Dispatch by action.** `_nat_rules` routes each `Nat` by its `action`: `DNAT` to the ADR-0008
   prerouting+forward path (untouched), `SNAT`/`MASQUERADE` to a new `_snat` path. Source NAT does
   not consult zones.
2. **One `postrouting` rule per entry.** In the ADR-0008 `postrouting` base chain, a source-NAT
   entry emits `oifname <out_interface>` → `ip saddr <source_nets>` → the source-NAT target, in that
   order (the ADR-0007 interface-then-address ordering). Rules land in the pre-existing base chain;
   no new chain is created.
3. **Source-net matching.** `source_nets` is split on `,` and each element reuses the ADR-0007
   address handling: a bare address is a scalar, a CIDR an nft `prefix`. A single element is matched
   directly; a list becomes an anonymous `set`. The match is `ip saddr` (family `ip`) — source NAT
   is IPv4 by construction.
4. **Target.** `MASQUERADE` (no `snat_to`) emits `{"masquerade": null}` — dynamic source NAT to the
   egress interface's own address. An explicit `SNAT(<addr>)` emits `{"snat": {"addr": <addr>,
   "family": "ip"}}`, mirroring the ADR-0008 `dnat` target's `family: ip`.
5. **No forward accept.** Source NAT emits *only* the `postrouting` rule — no filter `forward`
   accept, in deliberate contrast with `DNAT` (ADR-0008 §2).
6. **Family.** IPv4 by construction ([ADR-0002](0002-unified-inet-dual-stack.md)): the `ip saddr`
   match is itself the family guard and the `snat` target carries `family: ip`, so no `meta nfproto`
   guard is added.
7. **Fail closed** ([ADR-0004](0004-error-handling.md)): a source-NAT entry missing its egress
   interface or source network raises `ConfigError` rather than emitting a broken match.

## Consequences

- **Easier:** the common outbound-NAT case (masquerade a LAN behind the egress interface, or a
  static SNAT to a specific address) compiles to a correct `postrouting` rule, golden-testable
  without `nft`. The nat table + `postrouting` chain that ADR-0008 already emits are reused as-is.
- **Trade-off:** the rule matches only `oifname` + `ip saddr` — the `snat` file's
  PROTO/PORT/IPSEC/MARK/PROBABILITY narrowing columns are out of MVP scope (#156 rejects them at
  parse time). A real config needing them is a follow-up (YAGNI).
- **Trade-off:** all source-NAT rules share the base `postrouting` chain (no per-interface user
  chains), consistent with ADR-0006/0007/0008. Revisited when rule counts grow.

## Alternatives considered

- **A `forward` accept alongside the `postrouting` rule** (mirroring DNAT) — wrong: source NAT does
  not create a new forward path, so the accept would silently widen the `forward` policy. Rejected.
- **`snat to <egress-address>` for MASQUERADE** (resolving the interface address at compile time) —
  the egress address is dynamic and known only at packet time; `masquerade` is exactly nftables'
  answer for that. Rejected in favour of the dynamic target.
- **A `meta nfproto ipv4` guard on the postrouting rule** — redundant: the `ip saddr` match already
  pins the rule to IPv4 (and the `snat` target carries `family: ip`). Rejected.
- **Emitting the nat skeleton unconditionally for source NAT** — already handled: `_needs_nat_table`
  counts v4 source-NAT entries, so the ADR-0008 gating covers this without change. No new plumbing.
