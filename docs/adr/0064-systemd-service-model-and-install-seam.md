# ADR-0064: systemd service model and install seam

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

Epic #308 makes ShorewallNF **installable and boot-managed as a service** — the gap between "a
working compiler with lifecycle verbs" and `systemctl enable --now shorewallnf`. Two pieces of
that epic build on decisions that are not yet recorded, and building them on unsettled ground
would bake ad-hoc choices into shipped artifacts:

1. **The main `shorewallnf.service`** (separate task) wraps the lifecycle verbs
   (`ExecStart=shorewallnf start`, `ExecStop=shorewallnf stop`) and must be ordered relative to
   the existing boot-restore unit so the two do not fight.
2. **The install/packaging seam** is undefined. Today
   `packaging/systemd/shorewallnf-restore.service` (#207, [ADR-0030](0030-reboot-persistence-model.md))
   hardcodes `ExecStart=/usr/bin/shorewallnf restore`, there is no stated default config
   directory, and no documented unit-file install location. A pinned `/usr/bin` path is wrong
   for any install that puts the binary elsewhere (`/usr/local/bin` from a `pip install`, a
   distro that uses `/usr/sbin`), and there is nothing for the main service to build against.

This ADR settles those decisions first — the same pattern ADR-0030 used to fix the restore
contract before the unit landed — so the two units are authored against a stable seam.

Forces: **fail-closed and early** ([CLAUDE.md](../../CLAUDE.md)) — the host must never be
briefly reachable without its firewall; **YAGNI** — no install-time substitution machinery or
config knobs we do not need yet; **minimal deps** — the units are plain systemd, no generator
or templating step; **FHS** conventions for where config, state, and units live.

## Decision

### 1. Default config directory: `/etc/shorewallnf`

The default configuration directory is **`/etc/shorewallnf`** — the FHS home for host-local
configuration, and already the value used throughout the docs (`docs/operations.md`,
`docs/getting-started.md`). The verbs take an explicit `[config-dir]` positional
(`docs/operations.md`), so this is the documented default a service unit passes, not a hardcoded
constant in the compiler.

### 2. Unit-file install location

Shipped `.service` files live in the repo under `packaging/systemd/`. They install to the
**systemd vendor unit directory, `/usr/lib/systemd/system/`**, when placed by a distro package —
the location for units shipped by software rather than the local admin. A manual/local install
may instead copy them to **`/etc/systemd/system/`** (as `docs/lifecycle.md` shows); systemd reads
both, with `/etc` overriding `/usr/lib`. Both are valid; neither is baked into the unit.

### 3. Binary-path resolution: a non-absolute `ExecStart`

Shipped units name the binary **without a directory** — `ExecStart=shorewallnf restore`, not
`/usr/bin/shorewallnf`. systemd resolves a bare executable name against its compiled-in
executable search path (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin`), so the same unit
works whether the binary is installed to `/usr/bin` (distro package) or `/usr/local/bin`
(`pip install`) without edit or install-time substitution. This removes the `/usr/bin` pin and
keeps the packaging seam free of a templating step (YAGNI).

### 4. Two-unit boot model and ordering contract

Two units divide the boot responsibility:

- **`shorewallnf-restore.service`** (exists, #207) — early, **before `network-pre.target`**,
  `DefaultDependencies=no`, `Type=oneshot`, `RemainAfterExit=yes`, **fail-closed**. It re-applies
  the persisted ruleset (`/var/lib/shorewallnf/ruleset.json`) before any interface is configured,
  so there is no unprotected boot window (ADR-0030).
- **`shorewallnf.service`** (main, separate task) — starts at **`multi-user.target`**
  (`WantedBy=multi-user.target`), `ExecStart=shorewallnf start <config-dir>`,
  `ExecStop=shorewallnf stop <config-dir>`, `Type=oneshot`, `RemainAfterExit=yes`. It compiles
  and applies the **current** config.

The ordering contract: the main service is ordered **`After=shorewallnf-restore.service`**. The
restore unit establishes a protected state pre-network; the main service then brings up the
freshly compiled config at multi-user. Because the two are ordered sequentially — restore fully
completes (oneshot + `RemainAfterExit`) before the main service starts — there is **no
double-apply race**: each `apply`/`restore` is an atomic whole-ruleset replace (ADR-0010), and
they never run concurrently. There is **no unprotected window**: restore has already loaded a
firewall before the network came up, and the atomic replace at `start` swaps one complete
ruleset for another without an open gap.

## Consequences

- **Easier:** the main-service task (#308 child) has a settled seam to build on — config-dir
  default, install location, binary resolution, and the `After=` ordering are fixed here rather
  than reinvented in the unit. Shipped units are install-location-agnostic.
- **Trade-off:** relying on systemd's executable search path assumes a modern systemd (bare
  executable names in `ExecStart` are resolved since v239); an ancient systemd requiring an
  absolute path is not supported. Acceptable — the targets are current systemd distros.
- **Follow-up:** author `shorewallnf.service` with `After=shorewallnf-restore.service` per §4;
  document the install location(s) and `systemctl enable --now` in the install/getting-started
  docs (epic #308).

## Alternatives considered

- **Install-time path substitution** (a `@BINDIR@` token rewritten by the packaging step) —
  works, but adds a templating/build step to a repo that otherwise ships plain files, for no
  gain over systemd's own search path. Rejected (YAGNI).
- **Keep an absolute `ExecStart`, parameterized per distro** — every packager edits the unit;
  the shipped file is still wrong out of the box. Rejected in favour of the non-absolute name.
- **A single combined unit** doing restore-then-start — collapses the pre-network fail-closed
  restore and the multi-user config apply into one unit with conflicting ordering needs (one
  must run before the network, the other at multi-user). Two units with an explicit `After=`
  keep each correctly ordered. Rejected.
- **Config dir under `/usr/local/etc` or a bare `/etc/shorewall`-style path** — `/etc/shorewallnf`
  is the FHS-correct, already-documented default and avoids colliding with a co-installed
  Shorewall. Rejected the alternatives.
