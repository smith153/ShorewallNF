# ADR-0010: atomic scoped replacement of ShorewallNF's own tables

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

The generator emits a full ruleset as nftables JSON — `{"nftables": [{add table inet filter},
…chains/rules, {add table inet nat}, …]}` (ADR-0005/0008). To *apply* it we must load it into the
kernel, and a reload must be **deterministic**: loading over a stale copy of ShorewallNF's tables
must not leave orphaned chains or rules from a previous generation.

The netns test harness (`tests/netns_harness.py`) does this the blunt way: it prepends
`flush ruleset`, wiping the *entire* kernel nftables state before loading. That is fine for a
throwaway network namespace, but it is unacceptable for a real apply on a host where other software
(Docker, libvirt, a VPN, kubelet, another firewall front-end) owns its own nftables tables — a
`flush ruleset` would clobber all of them.

We need a reload that replaces **only** ShorewallNF's own `inet` table(s), atomically, in a single
transaction, leaving every co-resident table untouched.

Forces:

- **Scope must be derived, not hardcoded.** The ruleset defines `filter` always and `nat` only when
  a NAT entry needs it (ADR-0008). The replacement scope must track exactly the tables the ruleset
  defines — no more (would delete a table we did not create), no fewer (would leave a stale table).
- **Idempotent empty-or-replace.** A table may or may not already exist in the kernel. `delete table`
  on a non-existent table errors; `add table` on an existing one is a no-op. The prelude must handle
  both the first load and a reload uniformly.
- **Atomic.** nftables applies a JSON command list as one transaction: either the whole list commits
  or none of it does. The empty-and-reload must be one list so a mid-reload failure never leaves a
  half-applied firewall.
- **Pure and hermetically testable.** Building the payload needs no `nft` binary and no root — the
  imperative `nft` load stays in the applier's shell (ADR-0003); this task adds only the pure planner.

## Decision

1. **A pure planner in the applier.** `applier.atomic_load_payload(ruleset)` takes the *generated*
   nftables JSON (`{"nftables": […]}`) and returns a new payload of the same shape. It performs no
   I/O and does not mutate its input.
2. **Create-then-delete prelude, per table, in ruleset order.** For each `add table` command in the
   input, in the order it appears, the prelude emits `add table` then `delete table` for that same
   `{family, name}`. `add` makes the table exist (idempotent whether or not it pre-existed); the
   immediately following `delete` empties it. The pair leaves no table behind — the full ruleset that
   follows re-adds the table with its chains and rules.
3. **Scope derived from the input.** The tables are read out of the ruleset's `add table` commands,
   so adding or removing a table in the input (e.g. `nat` appearing only when NAT is configured)
   changes the prelude automatically. Nothing is hardcoded to a fixed `filter`/`nat` pair.
4. **One transaction, no `flush ruleset`.** The returned payload is a single `{"nftables": […]}`
   list: the whole prelude, then the entire input ruleset verbatim. There is no `flush ruleset` and
   no per-table `flush` — co-resident tables are never named, so they are never touched.

## Consequences

- **Easier:** a real apply can now replace ShorewallNF's firewall atomically without disturbing
  Docker/libvirt/VPN tables. The planner is pure, so it is unit-tested without `nft` or root.
- **Trade-off:** create-then-delete adds two prelude commands per table. This is deliberate — it is
  the idempotent idiom that works identically on a first load and a reload, avoiding a conditional
  "does this table exist?" probe that would break atomicity.
- **Follow-up:** wiring this planner into the netns harness (replacing its `flush ruleset`) and into
  a real `nft -f` apply path is separate work; this task delivers only the planner and its tests.

## Alternatives considered

- **`flush ruleset` (today's harness behaviour)** — replaces everything, clobbering co-resident
  tables. Acceptable only in a throwaway netns; rejected for a real apply.
- **Per-table `flush table` instead of delete** — `flush table` empties a table's rules but leaves
  its chains defined; the reload's `add chain` would then need to tolerate pre-existing chains, and a
  chain removed between generations would linger. `delete table` guarantees a clean slate. Rejected.
- **`delete table` without the preceding `add table`** — errors when the table does not yet exist
  (first load), aborting the whole transaction. The leading idempotent `add` is what makes the pair
  safe on both first load and reload. Rejected.
- **Hardcoding the `filter`+`nat` pair** — would delete a `nat` table on a filter-only config (the
  table may not exist) and would silently miss any future table. Deriving from the ruleset is both
  correct and future-proof. Rejected.
