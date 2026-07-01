# Project status

> The living snapshot of where ShorewallNF is. The **Epic Author** reads this first. Keep it
> current: when an epic is completed or the direction shifts, update this file in the same PR.

_Last updated: 2026-07-01 (compiler front-end merged: Reader, preprocessor, parser, IR; base generator underway)._

## Where we are

**Compiler front-end built; generation underway.** The AI pipeline and the **Architecture &
Code Standards epic (#3)** are complete, and the compiler now has a working front-end. The
Reader loads a config directory; the preprocessor resolves `params` substitution, `?if`
conditionals and `?FORMAT`/`?SECTION`; the tabular parser turns the preprocessed stream into
field-records; and the family-aware IR (zones with family-on-membership, interfaces, policies,
rules, NAT) is modeled per [ADR-0001](docs/adr/0001-ir-modeling.md)/[ADR-0002](docs/adr/0002-unified-inet-dual-stack.md).
`shorewallnf check <dir>` preprocesses a config end-to-end. **Next:** the `inet` nftables
Generator — its fail-closed base skeleton ([ADR-0005](docs/adr/0005-nftables-base-chain-layout.md))
is in review, with the `zones`/`interfaces` parsers and `compile` wiring following (epic #6).

Present:

- The compiler front-end under `src/shorewallnf/`: `reader.py`, `preprocessor.py`, `parser.py`,
  a full family-aware `ir.py`, and the base-skeleton `generator.py` (landing) — pure functional
  core / imperative shell per [ADR-0003](docs/adr/0003-design-approach.md).
- Python package skeleton with `ruff`/`mypy`/`pytest` and a CI workflow (lint/type/test).
  The behavioral **netns CI tier is stubbed** (`if: false`) pending the test-harness epic.
- The pipeline: role prompts (`pipeline/roles/`), labels, workflow, issue/PR templates,
  CODEOWNERS, Claude Code adapter.
- Design docs: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), the ADRs
  ([ADR-0001](docs/adr/0001-ir-modeling.md) IR modeling,
  [ADR-0002](docs/adr/0002-unified-inet-dual-stack.md) unified `inet`,
  [ADR-0003](docs/adr/0003-design-approach.md) design approach,
  [ADR-0004](docs/adr/0004-error-handling.md) error handling), the
  [module layout](docs/module-layout.md), and the foundation design spec under
  `docs/superpowers/specs/`.

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
3. **Zones & interfaces + base nft skeleton** — 🚧 **In progress.** Base `inet` generator
   (ADR-0005) in review; `zones`/`interfaces` parsers + `compile` wiring next (epic #6).
   `inet` tables/base-chains, stateful base, loopback, basic and family-appropriate interface options.
4. **Policy** — inter-zone default policies + logging.
5. **Basic rules engine** — `ACCEPT`/`DROP`/`REJECT`, proto/ports/ranges, `zone:host`,
   `?SECTION`s, `icmp`/`ipv6-icmp`.
6. **DNAT / port-forwarding (v4)** + the v6 direct-accept equivalent (IPv6 does no NAT).
7. **SNAT / MASQUERADE (v4).**
8. **Test harness** — golden-file infrastructure + the netns integration tier.
9. **CI/CD** — enable the netns job; expand the pipeline as needed.

### Post-MVP backlog

- Macros & custom actions (`Ping`, `Invalid`, `AwsDrop`)
- Conntrack **helpers** (the `conntrack` file: FTP/SIP/PPTP/…)
- Mangle / `TPROXY` / `DIVERT`
- Providers / policy routing
- QoS / traffic shaping (`tc*`)
- Advanced interface hardening options
- Shorewall-corpus comparison spike (nft↔iptables behavioral diffing)
- Import original Shorewall source into `orig_source/` for reference

## How to update this file

When an epic lands or scope changes: move it out of the backlog, note it under "Where we
are", and bump the _Last updated_ line — in the same PR that made the change.
