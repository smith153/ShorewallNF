# Concepts

ShorewallNF keeps Shorewall's declarative model — **zones**, **interfaces**, **policies**, and
**rules** — and compiles it directly into an **nftables** ruleset. This page explains that mental
model and how a configuration directory turns into concrete `inet` rules, at a user level. For the
compiler internals, the [design docs](#design-docs) link out to the in-repo architecture notes.

## The mental model

You describe your network as a few **zones**, bind each zone to the **interfaces** that reach it,
set a default **policy** for traffic between each pair of zones, then write **rules** for the
specific exceptions. ShorewallNF compiles that into a firewall that **defaults to deny** and only
admits what your policies and rules allow.

| Concept | Config file | What it declares |
|---|---|---|
| **Zone** | `zones` | A named part of your network (e.g. `net`, `loc`, `dmz`). |
| **Interface** | `interfaces` | Which network interface(s) belong to a zone, plus per-interface options. |
| **Policy** | `policy` | The *default* verdict for traffic from one zone to another. |
| **Rule** | `rules` | A *specific* exception evaluated before the policy default. |

Two names are special, exactly as in Shorewall:

- **`$FW`** — the firewall host itself. Traffic *to* it and *from* it is separate from traffic it
  merely *forwards* between other zones.
- **`all`** — a wildcard matching every zone, used to write catch-all policies.

The full list of files ShorewallNF reads is in the
[configuration file reference](reference/config-files.md).

## Zones, interfaces, and the firewall host

A **zone** is just a name. It becomes concrete when the `interfaces` file binds it to one or more
interfaces: a packet's zone is decided by the interface it arrived on (source zone) or is leaving
by (destination zone). The `$FW` zone has no interface of its own — it *is* the host — so traffic
to/from `$FW` is matched as the firewall's own input/output rather than forwarded traffic.

Because zones are named the same across IPv4 and IPv6 (there is no separate `net6`), a single set
of zone declarations covers both families; the family a given membership contributes is inferred
from its content. See [dual-stack, below](#dual-stack-one-config-both-families).

## Policies vs. rules: precedence

**Policies set the default stance; rules are the exceptions that override it.** For any two zones,
the `policy` file gives the fall-through verdict (`ACCEPT`, `DROP`, or `REJECT`) when no more
specific rule matched. The `rules` file lists per-connection exceptions — "allow SSH from `loc` to
`$FW`", "port-forward a TCP service to an internal host".

The precedence has two layers:

1. **Rules beat policies.** For a given zone pair, every matching rule is evaluated *before* that
   pair's policy default, so an explicit `ACCEPT` in `rules` wins over a `DROP` policy.
2. **Specific policies beat wildcards.** Among policies, a specific zone pair (`loc net`) is
   evaluated before a half-wildcard (`loc all`), which is evaluated before the catch-all
   (`all all`). So the most specific policy that matches is the one that applies.

If nothing matches at all, the firewall's fail-closed default takes over and the packet is dropped.

## How config compiles to nftables

ShorewallNF is a **compiler**. Your config directory flows through an explicit, family-aware
intermediate representation (IR) and out as nftables JSON:

```
config dir → Reader → Parser → IR → Validator → nftables Generator → Applier
```

Each stage has one job, and the IR in the middle knows nothing about nftables — that keeps parsing
and generation independently testable. The full pipeline is described in
[ARCHITECTURE.md](#design-docs).

### One `inet` table, three base chains

Everything lands in a single nftables table, `inet filter`, with three hooked base chains:

| Chain | Handles | Default |
|---|---|---|
| `input` | traffic *to* the firewall host (`$FW`) | **drop** |
| `forward` | traffic the firewall *routes between* other zones | **drop** |
| `output` | traffic *from* the firewall host | accept |

`input` and `forward` default to **drop** — that is the fail-closed foundation. Ahead of any of
your rules, each chain first accepts already-established/related connections (so return traffic
flows without a mirror rule), and `input` also accepts loopback.

### Where each rule and policy lands

Which base chain a policy or rule compiles into is decided by the role of `$FW`:

- destination is `$FW` → the **`input`** chain (traffic to the firewall);
- source is `$FW` → the **`output`** chain (traffic from the firewall);
- otherwise → the **`forward`** chain (traffic between two other zones).

Within a chain, the generator emits, in order: the established/related (and loopback) accepts, then
your **rules**, then the **policy** defaults. Since nftables evaluates a chain top-to-bottom, this
ordering is exactly what makes rules override policies and specific policies override the wildcards.
Zones are matched by their interfaces (`iifname` for the source, `oifname` for the destination).

### Dual-stack: one config, both families

nftables' `inet` family carries IPv4 and IPv6 in a single ruleset, so — unlike legacy Shorewall,
which iptables forced into separate `shorewall`/`shorewall6` programs — ShorewallNF keeps **one
family-aware IR** and emits **one `inet` ruleset** that is correct for both families. A rule that
doesn't mention a family applies to both; a rule pinned to one family (by an address literal or a
family-specific protocol such as `icmp` vs `ipv6-icmp`) is scoped to just that family. The
same intent is sometimes expressed differently per family — for example, exposing a service uses
`DNAT` on IPv4 but a plain accept to a global address on IPv6 — and the generator handles that
translation. The details are in
[ARCHITECTURE.md → Dual-stack](#design-docs).

## Design docs

The load-bearing design decisions live in the repository and are linked out to (rather than
duplicated) so this site stays user-facing:

- **[Architecture overview](https://github.com/smith153/ShorewallNF/blob/master/docs/ARCHITECTURE.md)**
  — the compiler pipeline, the IR, and dual-stack family scoping.
- **[ADR-0002 — unified `inet` dual-stack](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)**
  — one family-aware IR, one `inet` output.
- **[ADR-0005 — nftables base-chain layout](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0005-nftables-base-chain-layout.md)**
  — the fail-closed table and base chains.
- **[ADR-0006 — inter-zone policy compilation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0006-inter-zone-policy-compilation.md)**
  — how policies map to chains, and the specificity ordering.
- **[ADR-0007 — rules compilation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0007-rules-compilation.md)**
  — how rules layer ahead of the policy defaults.
- **[All ADRs](https://github.com/smith153/ShorewallNF/tree/master/docs/adr)** — the full decision log.

Ready to build one? See **[Getting started](getting-started.md)**.
