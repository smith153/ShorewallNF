# ADR-0006: inter-zone policy compilation & zone matching

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

[ADR-0005](0005-nftables-base-chain-layout.md) fixed the base `inet` skeleton — the table, the
fail-closed `input`/`forward`/`output` base chains, and the always-on stateful/loopback accepts.
The `policy` file (epic #7) defines the **default** action for traffic from one zone to another
(`<source> <dest> <action> [log_level]`, parsed into the `Policy` IR by task #89). The generator
must turn those policies into concrete nft rules appended to the base chains. This ADR fixes how a
policy maps to a chain, how zones are matched, the rule ordering, and the `$FW`/`all` special
cases — the rules engine (#74) reuses the same matching structure.

Forces:

- **Interface-based zone matching** for now: host/CIDR set matching (`ip saddr @zone`,
  [ADR-0002](0002-unified-inet-dual-stack.md)) is deferred until zone host-membership exists. A
  zone's interfaces come from the `interfaces` file (task #82).
- **Fail closed** ([ADR-0005](0005-nftables-base-chain-layout.md)): policy rules are the *last*
  rules in each chain, applying the default verdict to traffic no more-specific feature rule
  accepted.
- **Dual-stack in one `inet` ruleset** (ADR-0002): interface matching is family-neutral, so one
  rule covers IPv4 and IPv6.
- **Shorewall semantics:** `$FW` is the firewall host itself (its traffic is `input`/`output`,
  not `forward`), `all` is a wildcard zone, and a more specific policy must win over the `all`
  catch-alls.

## Decision

1. **Chain by the role of `$FW`.** A policy targets:
   - `forward` when neither side is the firewall zone — inter-zone forwarded traffic;
   - `input` when the **dest** is `$FW` — traffic to the firewall host;
   - `output` when the **source** is `$FW` — traffic from the firewall host.

   Source-`$FW` takes precedence, so a degenerate `$FW $FW` policy lands in `output`.

   An `all all` policy has neither side a firewall zone, so it lands in `forward` **only** — it is
   the inter-zone catch-all, not a universal default. Traffic to/from the firewall host keeps the
   ADR-0005 base-chain policies (`input` drop, `output` accept); `all all` deliberately does **not**
   seed `input`/`output` defaults (see Consequences).
2. **Zone matching by interface.** The source zone matches on `iifname`, the dest zone on
   `oifname`, against the zone's interface(s): a scalar `iifname "eth0"` for a single interface,
   an anonymous set `iifname { "eth0", "eth1" }` for several. `$FW` contributes no interface match
   (it is the host, not an interface); `all` contributes none (wildcard). An `all all` policy is
   therefore a bare verdict.
3. **Verdict + logging.** `ACCEPT`/`DROP`/`REJECT` map to the nft `accept`/`drop`/`reject`
   verdicts; when a policy carries a log level, an nft `log level <lvl>` statement precedes the
   verdict.
4. **Ordering.** Rules are emitted **specific pair first, then a single-`all` side, then `all all`
   last**, so a specific zone pair is evaluated before the wildcard defaults within a chain.
   Ordering is stable within a tier (policy-file order preserved).
5. **Fail closed on unmatchable zones.** A policy referencing a non-`$FW`, non-`all` zone with no
   interfaces cannot be matched; the generator raises a `ConfigError` rather than emit an empty
   match ([ADR-0004](0004-error-handling.md), fail-fast).

## Consequences

- **Easier:** the `policy` file compiles to correct, ordered, dual-stack default rules on top of
  the ADR-0005 skeleton; the interface-matching + chain-selection structure is reused by the rules
  engine (#74) and stays golden-file-testable without an `nft` binary.
- **Trade-off:** interface-only matching means host/CIDR-scoped zones are not yet narrowed
  (`ip saddr @zone` deferred until zone host-membership lands, ADR-0002); wildcard-interface
  (`eth+`) matching is likewise deferred (YAGNI).
- **Trade-off (`all all` scoping):** because `all all` compiles to a `forward` rule only, it does
  not govern firewall-host traffic. `all all DROP` is harmless (the `input` base policy already
  drops); but `all all REJECT` leaves firewall-bound traffic *dropped* rather than rejected, and
  `all all ACCEPT` does **not** open the firewall host (`input` stays `drop`). This diverges from
  Shorewall's universal `all all` and is accepted for now (YAGNI): a config wanting firewall-host
  defaults writes explicit `$FW`/`*→$FW` policies. Revisit if a real config needs it (#118).
- **Follow-up:** task #91 wires the `policy` file through the end-to-end compile path and validates
  the emitted ruleset with `nft -c`; the rules engine (#74) adds per-rule accepts *before* these
  defaults in the same chains.

## Alternatives considered

- **Per-zone-pair user chains** (a chain per zone pair, jumped to from the base chains) — mirrors
  Shorewall's generated structure and scales better with many rules, but is dead weight while
  policies are a handful of default rules. Deferred until the rules engine needs it (YAGNI).
- **Matching zones by address set instead of interface** — needs zone host-membership materialised
  into per-family sets (ADR-0002), which does not exist yet; interface matching is the available,
  correct-for-now key. Deferred.
- **Emitting policies in file order** — simpler, but a `net all DROP` listed before a
  `loc net ACCEPT` would shadow the specific pair. Specificity ordering avoids the footgun.
  Rejected.
