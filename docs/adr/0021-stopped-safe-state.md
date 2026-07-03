# ADR-0021: Stopped safe-state ruleset and no-lockout semantics

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

Shorewall's `stop` command does not tear the firewall down to an open (`ACCEPT`-all) or a fully
closed (`DROP`-all) state. Both are dangerous: the first exposes the host while it is
"stopped"; the second locks the operator out of a remote box with no way back in. Instead it
installs a small, fail-safe ruleset that keeps essential traffic flowing while the managed rules
are down — most importantly the admin-access rules an operator declares (e.g. SSH from a
management host) so a remote `stop` can never orphan them.

We already parse that admin-access declaration: the `stoppedrules` file is read into
`Ruleset.stopped_rules` by `parse_stopped_rules` (#210), reusing the `rules` grammar but
filter-only (no NAT). What is missing is the **generation** of the stopped ruleset itself — the
nftables the `stop` verb (#212) will install. This ADR fixes that ruleset's shape and its
no-lockout guarantee. It is generation only; installing it is #212.

The forces: it must be **self-contained** (a `stop` replaces the whole managed table, so the
stopped ruleset cannot lean on the running config's rules/policies/NAT); it must **fail closed**
by default (a stopped firewall that silently accepts everything is worse than useless); and it
must **never silently lock out** the operator, even when the config declares *zero* admin rules.

## Decision

Add a second generator entry point, `generate_stopped(ruleset)`, that emits a self-contained
`inet filter` table:

1. The same fail-closed base chains as the running ruleset (ADR-0005): `input`/`forward` default
   **drop**, `output` **accept**.
2. A fixed **no-lockout baseline**, always emitted regardless of admin rules: `ct state
   {established, related} accept` on `input` and `forward`, and `iifname lo accept` on `input`.
   This admits return traffic for connections the operator already holds (a live SSH session
   survives the `stop`) and loopback, without opening any new inbound port.
3. The parsed admin rules from `ruleset.stopped_rules`, translated by the **same** machinery as
   the running rules (`_translate_rules`/`_feature_rule`, ADR-0007) so they are family-correct
   (IPv4/IPv6) and chain-placed identically to normal rules.

`generate_stopped` consumes **only** `stopped_rules` — never the running `rules`, `policies`, or
`nats`. With zero admin rules the emitted ruleset is exactly the default-drop skeleton plus the
baseline: reachable for existing sessions and loopback, closed to everything new. There is no
all-ports-open path and no total-lockout path.

## Consequences

- The `stop` verb (#212) has a ready, golden-tested ruleset to install atomically (ADR-0010).
- The no-lockout baseline is a *policy* choice encoded in the generator, asserted by a golden
  snapshot and a zero-admin-rules test, so it cannot silently regress.
- Base-skeleton construction and rule translation are now shared helpers (`_filter_base`,
  `_translate_rules`) between `generate` and `generate_stopped`, keeping the two entry points in
  lockstep on family handling and chain layout.
- Trade-off accepted: the baseline admits *all* established/related traffic, not only that of
  admin flows. This mirrors the running ruleset's ADR-0005 baseline and is the price of not
  severing in-flight operator sessions during a `stop`.

## Alternatives considered

- **Flush to a bare default-drop (no baseline).** Rejected: a remote `stop` would sever the
  operator's own SSH session and leave no way back in — the exact lockout this ADR prevents.
- **Flush to `ACCEPT`-all.** Rejected: it exposes the host precisely when its managed rules are
  down; "stopped" must not mean "open".
- **Reuse the running `rules` in the stopped state.** Rejected: the stopped state must be a
  minimal, auditable safe state independent of the (possibly broken) running config — that
  separation is why `stoppedrules` is a distinct input.
