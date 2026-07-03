# ADR-0042: Mangle compilation — the prerouting mangle chain and action lowering

- **Status:** Accepted
- **Date:** 2026-07-03

## Context

[ADR-0001](0001-ir-modeling.md)/[#228](../../README.md) modelled the `mangle` file as a
family-aware `MangleRule` IR — a tagged union over `action` (`MARK`/`CONNMARK` with an optional
mask, `DIVERT`, `TPROXY(<port>)` with an optional mark) plus source/dest/proto/dport match
criteria. This ADR is the sibling generate step (#229): how the Generator lowers those rows into
the `inet` skeleton ([ADR-0005](0005-nftables-base-chain-layout.md)).

Packet marking must happen **before the routing decision** — a provider's `ip rule` selects a
routing table by fwmark ([ADR-0050](0050-policy-routing-artifact-model.md)), and that decision is
made right after `prerouting`. TPROXY likewise is only valid at `prerouting`, and DIVERT (keeping
an established transparent-proxy flow local) is a `prerouting` construct. So all four actions live
in one `prerouting` hook.

Forces:

- **Mark before routing:** the chain must hook `prerouting` at `priority mangle` (-150), ahead of
  the `nat` `dstnat` chain (-100) and the routing decision.
- **No output interface at prerouting:** the routing decision hasn't run, so `oifname` is
  unavailable. A rule can match the *source* zone (`iifname`), source/dest *host* literals
  (`ip[6] saddr`/`daddr`) and proto/ports — but **not a destination expressed as a bare zone**.
- **Family-aware** ([ADR-0002](0002-unified-inet-dual-stack.md)): a `TPROXY` needs a concrete
  family (`tproxy ip`/`tproxy ip6` in an `inet` table); a family-scoped rule carries a
  `meta nfproto` guard.
- **Fail closed** ([ADR-0004](0004-error-handling.md)): never emit a rule that silently marks more
  than written or that nft would reject.
- Pure `IR → JSON` ([ADR-0003](0003-design-approach.md)); reuse the ADR-0006/0007 zone/host
  matching where it applies.

## Decision

1. **One `prerouting` mangle chain in the `inet filter` table:**
   `{type filter hook prerouting priority -150 policy accept}`. `policy accept` because mangle is
   non-terminal — an unmatched packet falls through to routing/filtering. Emitted once, only when
   the config has any `mangle` rule.

2. **Rules are lowered in file order** into that chain (the parser preserves order, #228). Ordering
   is the operator's responsibility — e.g. a `DIVERT` row must precede a `TPROXY` row so an
   established proxy socket's traffic is kept local before the redirect.

3. **Match criteria** per rule: source zone → `iifname` (its interfaces); source/dest host literal
   → `ip[6] saddr`/`daddr`; `proto`/`dport`; plus a `meta nfproto` guard for a family-scoped rule.
   **A DEST given as a bare zone fails closed** — the out-interface is unknown at `prerouting`, so
   the criterion can't be honoured, and silently dropping it would mark more traffic than written
   (ADR-0004). DEST must be `-` or a host (`zone:host`, whose host is matched via `daddr`).

4. **Action lowering** (the non-terminal statement appended after the matches):
   - **MARK** → `{"mangle": {"key": {"meta": {"key": "mark"}}, "value": V}}`; **CONNMARK** → the
     same with `{"ct": {"key": "mark"}}`. A **mask** is a read-modify-write: `value` becomes
     `mark & ~mask | v` (`{"|": [{"&": [<mark>, ~mask]}, v]}`), so only the masked bits change.
   - **DIVERT** → `meta l4proto tcp` + `{"socket": {"key": "transparent"}} == 1` + optional
     `meta mark set` + `accept` — established transparent-proxy sockets stay local.
   - **TPROXY** → `{"tproxy": {"family": "ip"|"ip6", "port": P}}` (family from the rule, required —
     a `both`-family TPROXY fails closed) + optional `meta mark set` + `accept`.

5. **Family scoping:** a v4/v6-narrowed rule adds a `meta nfproto {ipv4|ipv6}` guard and, for
   `TPROXY`, selects `tproxy ip`/`tproxy ip6`. A dual-stack `MARK`/`CONNMARK`/`DIVERT` needs no
   guard; a dual-stack `TPROXY` can't pick a family and fails closed.

## Alternatives considered

- **A separate `mangle` table.** Rejected: nftables lets a `prerouting`/`mangle`-priority chain live
  in the existing `inet filter` table, keeping the single-table ADR-0005 shape; a second table adds
  no capability here (YAGNI).
- **Matching DEST zones via `oifname` at prerouting.** Rejected: `oifname` is not populated before
  the routing decision, so the match would silently never fire — worse than failing closed.
- **A `route`-type `output` chain for locally-generated traffic** (per `ipv4-mangle.nft`). Deferred
  (YAGNI): the reference config's marking is on forwarded/ingress traffic; add an output chain when
  a real need arrives.

## Consequences

- Mangle marking is source/host-based (the usual provider pattern); dest-zone-scoped marking is a
  fail-closed non-feature until a routing-aware model is designed.
- The `TPROXY` JSON shape (`{"tproxy": {...}}`) is not documented in `libnftables-json(5)`; it is
  taken from nftables' `json.c` and confirmed by the CI `nft --check` tier (this sandbox can't run
  `nft --check` — no `CAP_NET_ADMIN`). Packet-path behavior is validated by the netns test #231.
