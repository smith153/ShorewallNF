# ShorewallNF

**An nftables-native reimplementation of [Shorewall](https://shorewall.org/), written in Python.**

ShorewallNF reads a Shorewall-style configuration directory and compiles it — through an
explicit, family-aware intermediate representation — directly into **nftables** rules, with no
`iptables` or Perl in the path. One config produces family-correct dual-stack (IPv4 + IPv6)
output from a single unified `inet` ruleset.

!!! warning "Early development"
    ShorewallNF is under active development and not yet ready for production use. This site is
    a skeleton being filled in alongside the code.

## Why

Shorewall's design — declarative zones, interfaces, policies, and rules — has aged well, but
its `iptables`/Perl engine has not. ShorewallNF keeps the configuration model people know and
replaces the engine with a clean compiler pipeline that targets the modern kernel firewall:

```
config dir → Reader → Parser → IR → Validator → nftables Generator → Applier
```

- **nftables-native.** Emits nftables JSON via `python3-nftables`; no shelling out to `iptables`.
- **Dual-stack from one config.** A family-aware IR produces correct `inet` rules for v4 and v6.
- **Fail-closed.** Invalid config stops with one clear error rather than emitting a wrong
  firewall; `stop` drops to a safe state that still admits declared admin access.
- **Minimal footprint.** Standard library plus the system `python3-nftables` — nothing else.

## Next steps

- **[Getting started](getting-started.md)** — install and compile your first config.
- **[Configuration files](reference/config-files.md)** — the config directory ShorewallNF reads.
- **[Architecture & design decisions](https://github.com/smith153/ShorewallNF/tree/master/docs)** — the compiler pipeline and the ADRs, on GitHub.
