# ADR-0008: nat compilation — base nat-chain layout & DNAT match/target structure

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

[ADR-0005](0005-nftables-base-chain-layout.md) fixed the base `inet filter` skeleton (the table,
the fail-closed `input`/`forward`/`output` chains, the always-on stateful/loopback accepts);
[ADR-0006](0006-inter-zone-policy-compilation.md)/[ADR-0007](0007-rules-compilation.md) fixed how
`Policy`/`Rule` entries compile into it. The NAT epic (#75) adds the `Nat` IR: a `DNAT` from the
`rules` file port-forwards an external connection to an internal host (task #142 populates the IR;
this task compiles it). NAT needs its own base chains — nftables NAT hooks (`prerouting`,
`postrouting`) are distinct from the filter hooks — so this ADR fixes the nat skeleton and how a
v4 `DNAT` compiles: the prerouting match + `dnat` target, and the matching `forward` accept.

Forces:

- **NAT is IPv4-only** ([ADR-0002](0002-unified-inet-dual-stack.md)): IPv6 exposes a service by a
  plain `ACCEPT` to a global address (no NAT, task #144). A v4 `DNAT` target is inherently `ip`.
- **NAT hooks are separate** from filter hooks: a `dnat` needs a `prerouting` (dstnat-priority)
  base chain, an `snat`/`masquerade` a `postrouting` (srcnat-priority) one — neither exists in the
  ADR-0005 filter skeleton.
- **Fail closed** ([ADR-0005](0005-nftables-base-chain-layout.md)): the `forward` base chain drops
  by default, so a DNATed (NEW) connection is dropped unless an explicit `forward` accept admits it
  to the internal host — the nat rule alone is not enough.
- **Reuse ADR-0006/0007 zone matching** — a `Nat` names its source/dest zones exactly as a `Rule`
  does; interface matching and port-spec handling are identical.
- **Golden-file-testable** without an `nft` binary (epic #77).

## Decision

1. **A separate `inet nat` table, emitted as needed.** The nat counterpart to the ADR-0005 filter
   skeleton is a table `inet nat` holding two base chains — `prerouting` (`type nat`, hook
   `prerouting`, priority `dstnat` = `-100`) and `postrouting` (`type nat`, hook `postrouting`,
   priority `srcnat` = `100`), each `policy accept`. Unlike the always-present filter skeleton, the
   nat table + chains are emitted **only when the ruleset has NAT entries** (a config with no NAT
   carries no nat table). `postrouting` is part of the fixed skeleton even for a DNAT-only config —
   as ADR-0005's `output` chain is present with no rules — so the SNAT sibling (#76) only adds
   rules.
2. **A v4 `DNAT` emits two rules.** In `nat prerouting`: `iifname <source-zone-iface>` → protocol
   `dport` match → `dnat` target. In `filter forward`: the ADR-0006/0007 zone match
   (`iifname <source>` + `oifname <dest>`) → `ip daddr <host>` → protocol `dport` match →
   `accept`. The forward accept admits the post-DNAT connection to the internal host through the
   fail-closed forward chain; it is emitted before the policy defaults (as feature rules are,
   ADR-0007), so the default fall-through cannot shadow it.
3. **`dnat` target.** The IR `to` field is `host[:port]`. The target is
   `{"dnat": {"addr": <host>, "family": "ip", "port": <port>}}`; `port` is present only when `to`
   carries a `:port` **remap**. A remap **rewrites the destination port** in the `dnat` target, so
   the forward accept and the `dnat` match the *remapped* port while `prerouting` matches the
   *external* port. With no remap the forward accept matches the external port.
4. **Ports** reuse the ADR-0007 spec forms: a single port is a scalar integer, a comma-list an
   anonymous `set`, and `a:b` a `range`; a non-integer token passes through verbatim.
5. **Family.** NAT is IPv4 by construction (ADR-0002), so no `meta nfproto` guard is added: the
   `dnat` target carries `family: ip`, and the forward `ip daddr` match is itself v4-only. The
   prerouting `iifname`/`dport` matches are family-neutral; the `dnat`'s `family: ip` pins the
   translation to IPv4.
6. **Fail closed** ([ADR-0004](0004-error-handling.md)): a port match without a protocol, a zone
   with no interfaces, or a NAT entry this stage does not yet compile (an IPv6 `DNAT`, task #144;
   `SNAT`/`MASQUERADE`, #76) raises `ConfigError` rather than silently emitting nothing.

## Consequences

- **Easier:** the common port-forward compiles to a correct prerouting `dnat` plus the forward
  accept that makes it reachable, layered ahead of the policy defaults, golden-testable without
  `nft`. The `postrouting` skeleton is ready for the SNAT/MASQUERADE sibling (#76).
- **Trade-off:** the prerouting rule matches no original-destination address (the `Nat` IR has no
  such column yet), so a DNAT matches the port on *any* address arriving on the source interface —
  Shorewall's default when the ORIGINAL DEST column is empty. An explicit original-dest is a
  follow-up if a real config needs it (YAGNI).
- **Trade-off:** all DNATs share the base `prerouting`/`forward` chains (no per-zone-pair user
  chains), consistent with ADR-0006/0007. Revisited when rule counts grow.

## Alternatives considered

- **NAT chains in the existing `filter` table** — nftables allows `type nat` and `type filter`
  base chains in one table, but a separate `inet nat` table mirrors the ADR-0005 skeleton, keeps
  the nat plumbing self-contained, and matches how the ruleset reads. Rejected in favour of a
  dedicated table.
- **Always emitting the nat skeleton** (like the filter skeleton) — dead weight for the common
  config with no NAT. Gated on NAT presence instead (YAGNI).
- **Omitting the forward accept and relying on `ct status dnat accept`** — a single broad rule
  accepting anything DNATed is coarser than matching the specific internal host/port and diverges
  from the per-connection structure of ADR-0007. Rejected.
- **A `meta nfproto ipv4` guard on the prerouting rule** — redundant: the `dnat` target's
  `family: ip` already pins the translation, and NAT is v4-only by construction. Rejected.
