# Project status

> The living snapshot of where ShorewallNF is. The **Epic Author** reads this first. Keep it
> current: when an epic is completed or the direction shifts, update this file in the same PR.

_Last updated: 2026-07-08 (compiler complete end-to-end — Reader → preprocessor → parser → IR → resolver → validator → generator → applier — with reboot persistence and a boot-restore unit; several post-MVP features already landed)._

## Where we are

**The compiler compiles and applies, end to end.** The AI pipeline and the **Architecture &
Code Standards epic (#3)** are complete, and every stage of the pipeline is implemented — not
stubbed. A config directory flows Reader → preprocessor (`params`, `?if`, `?FORMAT`/`?SECTION`)
→ tabular parser → family-aware IR ([ADR-0001](docs/adr/0001-ir-modeling.md)/[ADR-0002](docs/adr/0002-unified-inet-dual-stack.md))
→ resolver (macro/action expansion) → validator → `inet` nftables-JSON generator → applier
(`nft --check`, atomic load, save/restore). The CLI exposes the full lifecycle:
`check`, `compile`, `apply`, `start`, `reload`/`restart`, `stop` (fail-safe stopped state),
`clear`, and `restore`. An applied ruleset is persisted to `/var/lib/shorewallnf/ruleset.json`
and reloaded at boot before the network comes up ([ADR-0030](docs/adr/0030-reboot-persistence-model.md)).

Config files consumed: `params`, `zones`, `interfaces`, `providers`, `policy`, `rules`, `snat`,
`conntrack`, `mangle`, `stoppedrules`. **Not yet consumed: a global settings file** (a
`shorewall.conf` analog) — the reader deliberately ignores it today; picking the supported
option set is the next design decision.

Present:

- The full compiler under `src/shorewallnf/`: `reader.py`, `preprocessor.py`, `parser.py`,
  family-aware `ir.py`, `resolver.py`, `validator.py`, `generator.py`, `applier.py`, plus the
  `macros.py`/`conntrack.py` built-in registries and `cli.py` — pure functional core /
  imperative shell per [ADR-0003](docs/adr/0003-design-approach.md).
- Reboot persistence + a fail-closed boot-restore systemd unit
  (`packaging/systemd/shorewallnf-restore.service`, [ADR-0030](docs/adr/0030-reboot-persistence-model.md)).
  **Not yet present: a main start/stop lifecycle unit** (`shorewallnf.service`) or a packaging/install story.
- Python package with `ruff`/`mypy`/`pytest` and a CI workflow (lint/type/test).
  The behavioral **netns CI tier is enabled** (`netns-integration` job): it installs
  iproute2 + nftables, runs the `-m netns` tier as root, and fails on a packet-path regression.
- The pipeline: role prompts (`pipeline/roles/`), labels, workflow, issue/PR templates,
  CODEOWNERS, Claude Code adapter, and a `pipeline-reconcile` GitHub Action that
  automates the judgment-free state transitions (#106).
- Design docs: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), 20+ ADRs in
  [`docs/adr/`](docs/adr/) (IR modeling through TPROXY/policy-routing), the
  [module layout](docs/module-layout.md), [`docs/lifecycle.md`](docs/lifecycle.md), and the
  foundation design spec under `docs/superpowers/specs/`. **No user-facing docs or docs-site
  tooling yet.**

## MVP definition of done

Basic, stateful, **dual-stack (IPv4 + IPv6)** routing and port-forwarding, **functionally
equivalent** to a real Shorewall config and **verified behaviorally** (netns), not by
byte-identical output. MVP targets a *documented subset* of that config — it does not have to
compile every line.

## Seed backlog

### MVP core epics (dependency-ordered)

0. **Architecture & Code Standards** — ✅ **Done.** ADR-0001–0004 (IR modeling, unified `inet`
   confirmed, design approach, error-handling conventions) and the module layout are merged;
   ARCHITECTURE.md and CLAUDE.md reference them.
1. **Project & CLI scaffolding** — ✅ **Done.** CLI entrypoint + `check` verb; `params` +
   `?if`/`?FORMAT`/`?SECTION` preprocessor (epic #4).
2. **Config-parsing framework + family-aware IR model** — ✅ **Done.** Tabular parser, the
   family-aware IR, and the parse-to-IR scaffold (epic #5; scaffold PR in final review).
3. **Zones & interfaces + base nft skeleton** — ✅ **Done.** `inet` tables/base-chains,
   stateful base, loopback, family-appropriate interface options (ADR-0005).
4. **Policy** — ✅ **Done.** Inter-zone default policies + logging (ADR-0006).
5. **Basic rules engine** — ✅ **Done.** `ACCEPT`/`DROP`/`REJECT`, proto/ports/ranges,
   `zone:host`, `?SECTION`s, `icmp`/`ipv6-icmp` (ADR-0007).
6. **DNAT / port-forwarding (v4)** — ✅ **Done.** Plus the v6 direct-accept equivalent (ADR-0008).
7. **SNAT / MASQUERADE (v4)** — ✅ **Done.** (ADR-0009).
8. **Test harness** — ✅ **Done.** Golden-file infra + the netns integration tier.
9. **CI/CD** — ✅ **Done.** netns job enabled; pipeline reconcile Action live.

Also landed ahead of the MVP line: macros & custom actions (ADR-0020), conntrack **helpers**
(ADR-0040/0041), mangle/marks (ADR-0042), providers/policy routing (ADR-0050), `TPROXY`
(ADR-0051), reboot persistence (ADR-0030), and the `orig_source/` reference import.

### Remaining gaps to a shippable product

These are the "product shell" around a working compiler — the path from "compiles correctly"
to "a stranger can install and trust it":

- **Global settings file** — a `shorewall.conf` analog. Needs an ADR to pick the supported
  option subset and define each option's nftables-native semantics (logging, dispositions,
  `IP_FORWARDING`, `DISABLE_IPV6`, `CLAMPMSS`, …). Legacy iptables/perl knobs are out of scope.
- **systemd + packaging** — a main `shorewallnf.service` (start/stop/reload lifecycle) beside
  the existing boot-restore unit, plus an install/path packaging seam.
- **User documentation + docs site** — no user-facing docs exist yet; stand up a docs site
  (MkDocs-Material on GitHub Pages) and start filling it.
- **Validator hardening** — the thinnest stage; deepen semantic checks so bad config fails
  fast with clear errors rather than emitting subtly-wrong rules.
- **Incremental reload** — `start`/`reload`/`restart` re-apply the full ruleset today; true
  incremental diffing is deferred (#175).

### Post-MVP backlog

- QoS / traffic shaping (`tc*`)
- Advanced interface hardening options
- Shorewall-corpus comparison spike (nft↔iptables behavioral diffing)

## How to update this file

When an epic lands or scope changes: move it out of the backlog, note it under "Where we
are", and bump the _Last updated_ line — in the same PR that made the change.
