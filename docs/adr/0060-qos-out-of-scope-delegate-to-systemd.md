# ADR-0060: Traffic shaping / QoS is out of scope — delegate to systemd

- **Status:** Accepted
- **Date:** 2026-07-08

> **Decision:** the owner (Sam) decided on 2026-07-08 to **hold QoS** and delegate traffic
> shaping to the systemd level (systemd-networkd traffic control) rather than build it into
> ShorewallNF. The QoS epic proposal ([#303](https://github.com/smith153/ShorewallNF/issues/303))
> is closed as **not-planned**. This ADR records that boundary durably.

## Context

Shorewall's `tcdevices`/`tcclasses` files express **QoS** as an HTB class hierarchy — a root
bandwidth per shaping device, per-class rate/ceiling/priority — with packet **marks** steering
flows into classes. A ShorewallNF QoS subsystem was proposed (epic
[#303](https://github.com/smith153/ShorewallNF/issues/303)) as a **third `tc` output channel**,
analogous to the policy-routing artifact channel ([ADR-0050](0050-policy-routing-artifact-model.md)):
a pure `IR → tc artifact` lowering plus an Applier that installs and tears down the
`tc qdisc`/`class`/`filter` hierarchy, sequenced atomically with the nft load and provider
routing. It would only ever *consume* the marks the mangle stage already
**sets** ([ADR-0042](0042-mangle-compilation.md), epic #203); the mark-*setting* groundwork exists.

But traffic shaping (`tc qdisc`/`class`/`filter`) is a Linux traffic-control concern that
**systemd-networkd already models declaratively** — traffic-control settings live in `.network`
units. Forces at play:

- **Minimal runtime surface** (CLAUDE.md YAGNI / minimal-deps): don't build a subsystem the
  platform already provides.
- **Lifecycle cost.** A `tc` channel means owning a `tc` apply/teardown lifecycle and its netns
  behavioral-test burden — real weight for a capability systemd covers.
- **Focus.** Keep ShorewallNF on the nftables firewall plus the routing/proxy glue it uniquely
  needs (providers, TPROXY local-delivery), not general traffic control.
- **Modest, mark-driven need.** The reference config's shaping needs are modest and mark-driven,
  and the fwmark classifier seam is already emitted by the mangle stage.

## Decision

We will **not** build a QoS/traffic-shaping subsystem in ShorewallNF. Traffic shaping is out of
scope; the recommendation is to configure QoS at the **systemd level** (systemd-networkd traffic
control), external to ShorewallNF.

The mangle stage continues to **set** marks, which an external systemd shaper can consume as `tc`
classifiers — but ShorewallNF emits **no `tc` artifacts** and runs **no `tc` applier channel**.
Epic [#303](https://github.com/smith153/ShorewallNF/issues/303) is closed as not-planned.

## Consequences

- **Easier:** no third output channel, no QoS IR/generator/applier, no `tc` netns tier — a smaller
  runtime surface with fewer moving parts to maintain and test.
- **Trade-off:** a config that relies on Shorewall's `tcdevices`/`tcclasses` is **not** reproduced
  by ShorewallNF; users wanting shaping configure systemd-networkd instead. The fwmark set by the
  mangle stage remains the classifier **seam** for that external shaper.
- **Follow-up:** if a concrete in-tool shaping requirement later appears (e.g. a real driver
  systemd can't cover), reopen [#303](https://github.com/smith153/ShorewallNF/issues/303) or
  supersede this ADR.

## Alternatives considered

1. **Build QoS as a native `tc` output channel (epic #303).** Rejected now: it duplicates a
   platform-provided capability, has no strong reference driver beyond Shorewall parity, and runs
   against YAGNI / minimal-surface. Held in reserve behind the follow-up above.
2. **Leave QoS silently in the backlog.** Rejected: an unrecorded scope boundary is ambiguous for
   contributors. An ADR makes the boundary — and its reversal condition — explicit.
