# ADR-0063: protective-check chain placement and disposition rendering

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

Epic #310 adds three ingress protective checks — **rpfilter** (reverse-path / anti-spoof),
**tcpflags** (illegal TCP-flag combinations), and **sfilter** (per-interface source-network
anti-spoof). Each is configured by a `*_DISPOSITION` + `*_LOG_LEVEL` pair whose scope
[ADR-0061](0061-shorewallnf-conf-settings-file.md) reserved but left unrendered, and the three
generator tasks (#380 rpfilter, #381 tcpflags, #382 sfilter) all build on two decisions that
are not covered by the existing skeleton:

1. **Where the checks slot into the ruleset.** [ADR-0005](0005-nftables-base-chain-layout.md)
   fixes the base skeleton — `input`/`forward` default-drop with a top-of-chain
   `ct state established,related accept`, in one `inet` table ([ADR-0002](0002-unified-inet-dual-stack.md)).
   The protective checks add structure that skeleton does not describe. rpfilter's canonical nft
   idiom is `fib saddr . iif oif missing`, which is only meaningful in a **prerouting** hook
   (before the routing decision picks input vs. forward). And placement relative to the
   established/related base-accept decides whether a check can be *shadowed* by it: a spoofed
   packet that matches an existing conntrack entry would be accepted by that rule before an
   anti-spoof check placed after it ever runs.
2. **How a check renders its disposition + log level.** All three share the same shape — an
   optional log line then a verdict — and the generator already renders exactly that for
   inter-zone policy rules ([ADR-0006 §3](0006-inter-zone-policy-compilation.md) "Verdict +
   logging": `generator._log` then `generator._verdict`, prefix via LOGFORMAT per ADR-0061). The
   checks need one shared model rather than three ad-hoc renderings.

Forces: fail-closed and early ([CLAUDE.md](../../CLAUDE.md)) — drop spoofed/invalid ingress
before it can benefit from the stateful base-accept; dual-stack in one `inet` ruleset
(ADR-0002); YAGNI — one small model the three tasks reuse, no per-check bespoke plumbing.

## Decision

### 1. A dedicated prerouting_raw filter chain for ingress anti-spoof

Add one chain to the ADR-0005 skeleton:

- **`prerouting_raw`** — `type filter hook prerouting priority raw` (numeric `-300`),
  `policy accept`. Named `prerouting_raw`, not `prerouting`: the mangle chain
  ([ADR-0042](0042-mangle-compilation.md)) already owns the base-chain name `prerouting` in
  `inet filter`, and base-chain names are unique per table.

It hosts, in order:

1. **rpfilter** — `fib saddr . iif oif missing` → disposition (default DROP).
2. **sfilter** — per-interface source-network anti-spoof → disposition (default DROP).

The prerouting hook fires **before** the routing decision, hence before the `input` and
`forward` hooks — so every packet these rules drop never reaches the ADR-0005
`ct state established,related accept` in `input`/`forward`. `priority raw` (`-300`) places the
chain ahead of conntrack (prio `-200`) in prerouting, so spoofed/invalid packets drop before a
conntrack entry is even created. `policy accept` keeps the chain non-terminal for everything the
checks do not explicitly drop — the routing decision and the base chains still apply.

### 2. tcpflags at the head of input and forward

**tcpflags** is emitted as the **first** rule of both the `input` and `forward` base chains —
ahead of the ADR-0005 `ct state established,related accept`. Illegal-flag packets are a property
of the packet, not the flow, so they must be caught even mid-connection; placing tcpflags after
the base-accept would let a malformed-flag packet on an established flow through.

tcpflags is not in the prerouting_raw chain: it is not an anti-spoof / routing-fib check, and
scoping it to the two forwarded/local base chains keeps it off the firewall's own `output`.

### 3. Anti-shadowing ordering rule

The invariant, stated once for all three checks: **no protective check may sit after the
ADR-0005 `ct state established,related accept`, and that accept may not sit before any check.**

- rpfilter + sfilter satisfy it structurally — the prerouting hook precedes the input/forward
  hooks, so their drops always precede that accept.
- tcpflags satisfies it by emission order — it is the head of `input`/`forward`, i.e. emitted
  *before* the base-accept rule (which ADR-0005 lists first among the always-on rules; tcpflags
  is prepended ahead of it).

This is the mirror of ADR-0005's own shadowing note ([§Consequences](0005-nftables-base-chain-layout.md)):
there the base-accept must precede feature rules; here the protective checks are the one class
of rule that must precede *it*, because they gate packets the accept would otherwise wave
through.

### 4. Shared `Disposition` model and rendering

A single enum, reused by all three checks (and available to later gating subsystems):

```
Disposition = ACCEPT | DROP | REJECT | CONTINUE
```

A check renders to an ordered nft statement list as: **optional `log`, then verdict.**

- **log** — emitted only when the check's `*_LOG_LEVEL` is set. Level is that `*_LOG_LEVEL`;
  prefix is rendered from `LOGFORMAT` per [ADR-0061](0061-shorewallnf-conf-settings-file.md)
  (its `%s` slots filled with the chain name and the disposition, length-checked against the
  kernel prefix limit — an over-long prefix fails fast, [ADR-0004](0004-error-handling.md)) —
  identical to the policy-rule rendering the generator already does
  ([ADR-0006 §3](0006-inter-zone-policy-compilation.md) "Verdict + logging": `generator._log`
  then `generator._verdict`).
- **verdict** — `ACCEPT → accept`, `DROP → drop`, `REJECT → reject`. **`CONTINUE` emits no
  terminal verdict**: the matched packet falls through to the rest of the chain (the log line, if
  any, is still emitted). CONTINUE is what lets an operator log-only a check without dropping.

Each check maps its own `*_DISPOSITION` onto this enum and its `*_LOG_LEVEL` onto the log level;
the three renderings differ only in the *match* that precedes this shared tail. Shorewall's
default disposition for all three is DROP.

### 5. Family correctness (one `inet` ruleset)

- **rpfilter** — `fib saddr . iif oif missing` is **family-neutral**: one rule matches both IPv4
  and IPv6 in the `inet` chain, no `nfproto`/`ip`/`ip6` guard.
- **tcpflags** — matches TCP header bits (`tcp flags …`), **family-neutral**: one rule per base
  chain covers both families.
- **sfilter** — source networks are per-family, so it scopes each family explicitly: `ip saddr
  <v4 nets>` and `ip6 saddr <v6 nets>` as separate rules (each carrying an implicit family match)
  in the single `inet` prerouting_raw chain. A config with only v4 nets emits only the `ip saddr`
  rule; only v6, only `ip6 saddr` (ADR-0002).

Example sfilter drop for a documentation-range source set (illustrative):

```
ip saddr { 192.0.2.0/24, 198.51.100.0/24 } iifname "ethX" log prefix "…" drop
ip6 saddr { 2001:db8::/32 } iifname "ethX" log prefix "…" drop
```

## Consequences

- **Easier:** #380/#381/#382 share one `Disposition` enum and one render-tail
  (`log?` → `verdict`), so the checks differ only in their match; placement is decided once, and
  the prerouting hook gives anti-spoof a single early choke point that cannot be shadowed by the
  stateful base-accept. Dual-stack falls out of the `inet` chain for free.
- **Trade-off:** the skeleton now has a fourth base chain (`prerouting_raw`) that exists even when no
  protective check is configured — but its `policy accept` and empty body make it inert, and a
  fixed skeleton is ADR-0005's chosen shape. sfilter emits up to two rules per interface (one per
  family present) rather than one family-neutral rule; that is inherent to per-family source nets,
  not avoidable in a single `inet` ruleset.
- **Follow-up:** #380/#381/#382 implement the three checks against this model; the `Disposition`
  enum lives beside the IR the three tasks consume. A future gating subsystem (e.g. blacklist,
  ADR-0061 §scope) can reuse the same enum and render-tail.

## Alternatives considered

- **All three checks at the head of `input`/`forward`** (no prerouting_raw chain). Rejected:
  - rpfilter's `fib saddr . iif oif missing` idiom belongs in **prerouting**, before the routing
    decision — replicating it in both input and forward is redundant and loses the natural
    "before conntrack" ordering.
  - It gives no single choke point for ingress anti-spoof; sfilter's per-interface source nets
    would be duplicated across two chains.
  - Placing anti-spoof *at* the head of input/forward still works only because it precedes the
    base-accept there, but it runs **after** conntrack has already tracked the spoofed packet;
    the prerouting_raw chain drops it earlier (`priority raw`). Early ingress drop before the
    conntrack base-accept is the whole point, so the prerouting_raw chain is preferred.

  tcpflags is the one check that *is* kept at the head of input/forward — it is a packet-property
  check, not a routing-fib/source anti-spoof check, so it has no reason to move to the
  prerouting_raw chain and every reason to guard both the local and forwarded paths.

- **Per-check disposition rendering** (each of the three emits its own log+verdict logic).
  Rejected as needless duplication — the shape is identical to the existing policy-rule rendering,
  so one shared `Disposition` model + render-tail is the YAGNI choice.

- **A `reject`-by-default disposition.** Rejected — Shorewall's defaults are DROP for all three
  (a silent drop of spoofed/malformed ingress leaks less than an informative reject); REJECT
  remains available via the enum when an operator sets it.
