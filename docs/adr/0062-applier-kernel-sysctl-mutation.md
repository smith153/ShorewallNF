# ADR-0062: applier kernel-sysctl mutation & rollback semantics

- **Status:** Accepted
- **Date:** 2026-07-08

> **Numbering:** `0062` is reserved by task #322 (this ADR). The parent epic is #309; the settings
> file, frozen `Settings` model, and option scope are fixed by [ADR-0061](0061-shorewallnf-conf-settings-file.md),
> which flags this sysctl step as a boundary to design here.

## Context

[ADR-0061](0061-shorewallnf-conf-settings-file.md) introduced `shorewallnf.conf` and a frozen
`Settings` IR carrying three tri-state kernel toggles — `IP_FORWARDING` (`On`/`Off`/`Keep`),
`LOG_MARTIANS` and `ROUTE_FILTER` (`Yes`/`No`/`Keep`) — but deliberately deferred *how* they are
applied, flagging it as the applier's **first kernel mutation outside nftables**. This ADR fixes
that: which sysctls each toggle drives, where in the apply sequence they run, and how a sysctl
failure is rolled back.

Forces:

- **Family-aware (ADR-0002).** ShorewallNF compiles one `inet` config to family-correct output.
  Forwarding exists for both families (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`);
  martian logging and reverse-path filtering are IPv4-only `conf` keys (no IPv6 kernel equivalent).
- **`Keep` must touch nothing.** The all-defaults `Settings` (absent file, or an absent key) is
  all-`Keep`; adopting the file must not silently flip a kernel toggle the operator never set.
- **Fail-closed, no half-applied firewall (ADR-0004/0010/0021).** A compiler that leaves the box in
  a half-mutated state is worse than one that refuses. The nft ruleset already loads as one atomic
  transaction (ADR-0010); the sysctl step must not undermine that guarantee — in particular it must
  never enable forwarding while the firewall that governs forwarded traffic is *not* in place.
- **Testable without root.** Following the imperative-shell discipline (ADR-0003) and the existing
  `ip`-based routing seam, the string→argv mapping must be a pure function so it is unit-tested by
  capturing argv; only the actual `sysctl` invocation needs privilege.

## Decision

We will lower the three `Settings` toggles to `sysctl` writes in the applier shell, applied
**after** the atomic nft load, with a snapshot-and-restore rollback.

### 1. Key mapping

A pure `applier.sysctl_plan(settings) -> list[(key, value)]` maps each **non-`Keep`** toggle to its
sysctl writes, in deterministic order; `On`/`Yes` → `"1"`, `Off`/`No` → `"0"`. A `Keep` (or absent)
toggle contributes **no entry**, so the kernel value is untouched.

| Setting | Sysctl keys | Family |
|---|---|---|
| `IP_FORWARDING` | `net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding` | v4 + v6 |
| `LOG_MARTIANS` | `net.ipv4.conf.all.log_martians`, `net.ipv4.conf.default.log_martians` | v4 |
| `ROUTE_FILTER` | `net.ipv4.conf.all.rp_filter`, `net.ipv4.conf.default.rp_filter` | v4 |

`all` + `default` cover existing and future interfaces without enumerating them (YAGNI: per-interface
scoping is not modeled until a concrete need arrives).

### 2. Ordering — after the atomic nft load

`apply_sysctls(settings)` runs **after** `apply_ruleset` (the ADR-0010 scoped replace), mirroring the
provider/tproxy routing artifacts that also apply post-load. This ordering is what makes
`IP_FORWARDING=On` fail-closed: forwarding is enabled only once the firewall governing forwarded
traffic is loaded, never in a window before it. In the CLI the step sits between the nft load and the
save/persist step, so a sysctl failure aborts before the config is persisted.

### 3. Snapshot and rollback — fail-closed

`apply_sysctls` snapshots every target key's current value (`sysctl -n`) **before** writing, then
writes the plan in order (`sysctl -w key=value`). On the **first** write failure it restores every
already-written key to its snapshot (reverse order, best-effort) and raises `ConfigError`, so a
partial failure never leaves the toggles half-set. A key whose snapshot read failed (absent key) is
not restored. Because the nft ruleset committed earlier as its own atomic transaction, a rolled-back
sysctl step leaves a fully-loaded firewall with the kernel toggles at their prior values — never a
half-applied one.

### 4. Scope of the verbs

The sysctl step is wired into the running-firewall apply paths — `apply`, `start`, `reload`,
`restart` — which all load the running ruleset. `stop`/`clear`/`restore` are left untouched (YAGNI):
they are the safe-state/teardown paths and do not carry the running `Settings` intent.

## Consequences

- The applier gains its **first non-nftables kernel mutation**, with a pure `sysctl_plan` planner
  (unit-tested without root) and a privileged `apply_sysctls` shell step (proven in the netns tier).
- **Backward-compatible:** an absent `shorewallnf.conf` is all-`Keep`, so `sysctl_plan` is empty and
  `apply_sysctls` is a no-op — no kernel toggle changes and no golden output moves.
- **Fail-closed by construction:** forwarding is enabled only after the firewall is loaded, and a
  sysctl failure rolls its own batch back and aborts before persisting the config.
- **Follow-up:** IPv6-family gating (`DISABLE_IPV6`, #311) and per-interface protective checks
  (#310) are separate settings; if `net.ipv6.*` is absent on an IPv6-disabled host, an
  `IP_FORWARDING` write fails and rolls back — acceptable until that gating exists.

## Alternatives considered

- **Sysctls before the nft load.** Rejected: it makes nft the final irreversible step, but opens a
  fail-**open** window — `IP_FORWARDING=On` would enable forwarding before the new firewall governs
  forwarded traffic. Applying after the load closes that window.
- **No snapshot; leave sysctls as written on partial failure.** Rejected: a mid-batch failure would
  leave some toggles flipped and others not, a silent half-applied state contrary to fail-closed
  (ADR-0004). Snapshot-and-restore makes the batch all-or-nothing.
- **Per-interface keys instead of `all`/`default`.** Rejected (YAGNI): it requires enumerating
  interfaces and re-applying on interface changes; `all`/`default` express the whole-box intent the
  setting carries today.
- **Write sysctls via a persisted `sysctl.d` drop-in.** Rejected: it defers the effect to a reload
  and splits the apply across two mechanisms; a direct `sysctl -w` mutates live, matching the apply's
  "make it so now" contract, and reboot-persistence is a separate concern (ADR-0030).
