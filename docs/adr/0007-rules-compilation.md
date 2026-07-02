# ADR-0007: rules compilation & match structure

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

[ADR-0006](0006-inter-zone-policy-compilation.md) fixed how the `policy` file's inter-zone
*defaults* compile: chain by the role of `$FW`, zone matching by interface, specificity ordering,
appended last in each base chain. The rules engine (epic #74) adds the `rules` file's
**per-connection** rules — an explicit `<action> <source> <dest> [proto] [dport] [sport]` that must
be evaluated *before* those defaults so an explicit `ACCEPT` wins over the zone-pair policy. This
ADR fixes how a `Rule` compiles: where it lands relative to the policy defaults, the order of match
statements within a rule, tcp/udp protocol & port matching, and family handling. The sibling
generator tasks build on it — ICMP (#122), `zone:host` narrowing (#123), `?SECTION` ordering
(#124), and the end-to-end compile (#125).

Forces:

- **Explicit rules beat defaults** (Shorewall semantics): a rule's verdict must be reachable before
  the [ADR-0006](0006-inter-zone-policy-compilation.md) fall-through in the same chain.
- **Reuse ADR-0006's zone matching** — chain selection and interface matching are identical; a
  `Rule` names zones (or `zone:host`) exactly as a `Policy` names zones.
- **Dual-stack in one `inet` ruleset** ([ADR-0002](0002-unified-inet-dual-stack.md)): tcp/udp and
  port matches are family-neutral, so a `both` rule needs no family guard.
- **Golden-file-testable** without an `nft` binary (epic #77): the emitted JSON must be the
  canonical form nft itself round-trips.

## Decision

1. **Placement: feature rules before policy defaults.** `generate()` emits, per base chain, the
   [ADR-0005](0005-nftables-base-chain-layout.md) stateful/loopback accepts, then the feature
   rules, then the ADR-0006 policy defaults. nft evaluates a chain in insertion order, so an
   explicit rule verdict is reached before the zone-pair default. Feature rules keep `rules`-file
   order (`?SECTION` reordering is #124).
2. **Chain & zone matching reuse ADR-0006.** A rule picks its chain by the role of `$FW` (source
   `$FW` → `output`, dest `$FW` → `input`, else `forward`) and matches each non-`all`, non-`$FW`
   side by its zone interface(s) — a scalar `iifname`/`oifname` or an anonymous set — exactly as a
   policy does. The `zone:host` token's host part is ignored here; address narrowing is #123.
3. **Match-statement order within a rule:** interface matches (`iifname` then `oifname`) → address
   narrowing (#123) → connection-state (#124) → L4 protocol/port matches → verdict. This fixed
   order keeps output deterministic and golden-testable as the sibling tasks add their matches.
4. **Protocol & ports (tcp/udp).** A proto-only rule emits `meta l4proto <proto>` (family-neutral).
   With ports we emit one payload match per column — `<proto> dport` before `<proto> sport` — and
   *no* separate protocol match: nft folds the protocol dependency back in when the rule loads, so
   the bare payload match is the canonical form that both round-trips on `nft list` and loads under
   `nft -c`. Port spec forms: a single port is a scalar integer, a comma-list an anonymous `set`,
   and `a:b` a `range`; a set element may itself be a range. A token that is not a plain integer
   passes through verbatim (nft resolves service names).
5. **Family.** tcp/udp and port matches are family-neutral, so a `Family.BOTH` rule adds no family
   guard — it matches v4 and v6 in the one `inet` table (ADR-0002). Family-pinned scoping is
   realised by the family-specific match that pins it: `icmp`/`ipv6-icmp` for ICMP (#122) and
   `ip`/`ip6 saddr`/`daddr` for address narrowing (#123). This ADR's match structure hosts those;
   it emits no `meta nfproto` guard of its own.
6. **Fail closed** ([ADR-0004](0004-error-handling.md)): a port match without a protocol, or a zone
   with no interfaces, raises `ConfigError` rather than emit a broken match.

## Consequences

- **Easier:** the common `rules` case (verdict + tcp/udp + ports) compiles to correct, ordered,
  dual-stack rules layered ahead of the policy defaults, golden-testable without `nft`.
  #122/#123/#124 slot their matches into the fixed order; #125 wires the `rules` file end-to-end
  and `nft -c`-validates it.
- **Trade-off:** all feature rules share the base chains (no per-zone-pair user chains yet, as in
  ADR-0006) — fine for a handful of rules, revisited when rule counts grow (YAGNI).
- **Trade-off:** an ICMP rule fed through the generic proto path would emit `meta l4proto icmp`
  rather than the family-correct `icmp`/`ipv6-icmp`; #122 specialises it. No end-to-end path emits
  rules until #125, so nothing relies on that interim shape.
- **Limitation — ESTABLISHED/RELATED are accept-only (#138).** The `?SECTION` state gate this ADR
  hosts sits *after* [ADR-0005](0005-nftables-base-chain-layout.md)'s top-of-chain
  `ct state {established, related} accept`, so a `DROP`/`REJECT` in those two sections is
  unreachable. The Validator rejects that dead case up front (fail-closed); an `ACCEPT` there is a
  redundant no-op. INVALID/NEW are unaffected. A conditional base accept (FASTACCEPT-off) is a
  future ADR, not built here.

## Alternatives considered

- **A separate `meta l4proto <proto>` match alongside each port match** — redundant: nft
  regenerates that dependency on load and folds it away on list, so emitting it would diverge from
  the canonical JSON and break golden diffs. Rejected.
- **Per-zone-pair user chains** (a chain per zone pair, jumped to from the base chains) — mirrors
  Shorewall's generated structure and scales better, but is dead weight at current rule counts.
  Deferred, as in ADR-0006 (YAGNI).
- **Emitting feature rules after the policy defaults** — would let the zone-pair default shadow an
  explicit rule, contradicting Shorewall semantics. Rejected.
