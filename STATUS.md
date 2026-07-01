# Project status

> The living snapshot of where ShorewallNF is. The **Epic Author** reads this first. Keep it
> current: when an epic is completed or the direction shifts, update this file in the same PR.

_Last updated: 2026-06-30 (foundation)._

## Where we are

**Foundation only.** The repository scaffolding and the AI development pipeline exist; there
is **no compiler yet**. The package `src/shorewallnf` is a stub. The next work is the MVP
backlog below, starting with the Architecture epic.

Present:

- Python package skeleton with `ruff`/`mypy`/`pytest` and a CI workflow (lint/type/test).
  The behavioral **netns CI tier is stubbed** (`if: false`) pending the test-harness epic.
- The pipeline: role prompts (`pipeline/roles/`), labels, workflow, issue/PR templates,
  CODEOWNERS, Claude Code adapter.
- Design docs: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), ADR-0002 (unified `inet`),
  and the foundation design spec under `docs/superpowers/specs/`.

## MVP definition of done

Basic, stateful, **dual-stack (IPv4 + IPv6)** routing and port-forwarding, **functionally
equivalent** to a real Shorewall config and **verified behaviorally** (netns), not by
byte-identical output. MVP targets a *documented subset* of that config — it does not have to
compile every line.

## Seed backlog

### MVP core epics (dependency-ordered)

0. **Architecture & Code Standards** — ADR-0001 (IR modeling: dataclasses vs pydantic),
   confirm ADR-0002 details, module layout, error-handling conventions, and the overall design
   approach (functional-core vs OOP, dispatch strategy, exception patterns).
1. **Project & CLI scaffolding** — CLI entrypoint; `params` + `?if`/`?FORMAT`/`?SECTION` preprocessor.
2. **Config-parsing framework + family-aware IR model.**
3. **Zones & interfaces + base nft skeleton** — `inet` tables/base-chains, stateful base,
   loopback, basic and family-appropriate interface options.
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
