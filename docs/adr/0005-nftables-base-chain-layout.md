# ADR-0005: nftables base-chain layout

- **Status:** Accepted
- **Date:** 2026-07-01

## Context

[ADR-0002](0002-unified-inet-dual-stack.md) committed ShorewallNF to a single family-aware IR
and **`inet`-family** nftables output. The generator (epic #6) emits that output starting with a
**base skeleton** — the table, the hooked base chains, and the always-on rules (stateful accept,
loopback) — that every later feature hangs off: policy default rules (#7), the rules engine
(#74), and NAT chains (#75/#76) all add to *these* chains. Getting the skeleton wrong is
expensive to change once features depend on it, so the layout is fixed here.

Forces:

- **Dual-stack in one ruleset** (ADR-0002): the `inet` family carries IPv4 and IPv6 together, so
  there is one table and one set of base chains, not a v4 tree and a v6 tree.
- **Fail closed** ([CLAUDE.md](../../CLAUDE.md)): a firewall that defaults to *permit* is worse
  than one that refuses traffic. Unmatched inbound/forwarded traffic must be dropped, not passed.
- **Stateful** (STATUS.md MVP): established/related return traffic must be accepted up front, or
  every rule would need an explicit return-path counterpart.
- JSON is emitted for `libnftables` via `python3-nftables` (ADR-0002, ARCHITECTURE.md).

## Decision

1. **One `inet` table, named `filter`.** A single table `inet filter` holds the whole ruleset.
2. **Three base chains**, each `type filter` at the standard filter priority (`prio 0`):
   - `input` — hook `input`, **policy `drop`**.
   - `forward` — hook `forward`, **policy `drop`**.
   - `output` — hook `output`, **policy `accept`**.
   Input and forward are fail-closed; the firewall's own output is permitted by default (the
   policy file, epic #7, can tighten it later).
3. **Always-on base rules**, emitted before any feature rules:
   - `input`: `ct state established,related accept`, then `iifname "lo" accept`.
   - `forward`: `ct state established,related accept`.
   - `output`: none — the chain policy already accepts.
4. **JSON shape.** Output is the `python3-nftables` schema: a top-level `{"nftables": [ … ]}`
   whose list is `add` commands for the table, each chain, then each rule (an `expr` list of
   match/verdict statements). Ordering is table → chains → rules so a single load applies cleanly.
5. **Family-neutral base.** None of the base rules carry an `nfproto`/`ip`/`ip6` guard, so each
   matches both families in the one `inet` ruleset (ADR-0002). Per-family scoping appears only on
   feature rules that need it.

## Consequences

- **Easier:** a stable, fail-closed foundation every feature epic extends by appending chains and
  rules; golden-file-testable as pure `IR → JSON` (no `nft` binary needed); dual-stack for free.
- **Trade-off:** the base skeleton is currently fixed (independent of the specific zones/rules) —
  zone sets and per-rule chains are added *from the IR* by later epics; the generator's
  `generate(ruleset)` signature already takes the ruleset so those extensions need no API change.
- **Follow-up:** epic #7 (policy) turns the drop defaults into policy-file-driven last rules;
  epics #74/#75/#76 add the rules/NAT chains; epic #6's compile task validates the emitted ruleset
  with `nft -c` once the netns test tier (#77/#78) is available.
- **Limitation — ESTABLISHED/RELATED sections are accept-only (#138).** Because rule 3 accepts
  `ct state {established, related}` at the *top* of `input`/`forward`, any `rules`-file rule in the
  `?SECTION ESTABLISHED` or `?SECTION RELATED` block (which the generator gates on the same state,
  [ADR-0007](0007-rules-compilation.md)) is emitted *after* that accept: an `ACCEPT` there is a
  redundant no-op, and a `DROP`/`REJECT` is unreachable. The Validator
  ([module-layout](../module-layout.md)) fails fast on the dead `DROP`/`REJECT` case (fail-closed,
  [ADR-0004](0004-error-handling.md)) rather than emit a rule that can never match; INVALID and NEW
  are unaffected (their states are not in this accept). Making the base accept *conditional* (a
  FASTACCEPT-off mode, so mid-connection policy could apply) is deliberately **out of scope** here —
  a future ADR if a real need arrives.

## Alternatives considered

- **Separate v4/v6 tables** (`ip`/`ip6`) — mirrors legacy Shorewall's two programs, but discards
  the `inet` advantage ADR-0002 chose. Rejected.
- **Default-accept base chains with explicit drop rules** — equivalent behaviour, but a momentary
  or misordered ruleset would permit traffic; policy `drop` is fail-closed by construction.
  Rejected.
- **Materialising zone sets in the base skeleton now** — the generator will materialise zones into
  per-family sets (ADR-0002), but with no rules referencing them yet those sets are dead weight.
  Deferred to the epic whose rules first use them (YAGNI).
