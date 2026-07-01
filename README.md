# ShorewallNF

**ShorewallNF** is a from-scratch reimplementation of [Shorewall](https://shorewall.org) that
targets **nftables** instead of iptables, written in **Python**. It reads Shorewall-style
configuration files and compiles them into an nftables ruleset.

> **Status: pre-MVP scaffolding.** The repository foundation and the AI development pipeline
> are in place; the compiler itself is being built issue-by-issue by that pipeline. There is
> no working compiler yet.

## Why

Shorewall is a mature, much-loved firewall configuration system, but it is built around
iptables. nftables is the modern replacement — and its `inet` address family lets a single
ruleset serve both IPv4 and IPv6, removing the split that forced Shorewall to ship separate
`shorewall` and `shorewall6` programs. ShorewallNF keeps the familiar configuration model and
compiles it to native nftables.

## MVP goal

Basic, stateful, **dual-stack (IPv4 + IPv6) routing and port-forwarding**, modeled on a real
Shorewall configuration. Success is defined as being **functionally equivalent** to that
configuration, **verified behaviorally** (not byte-identical output — the original emits
iptables, we emit nftables). See [`STATUS.md`](STATUS.md) for the current backlog and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design.

## How this project is built

ShorewallNF is developed almost entirely by **AI agents**, coordinated through GitHub issues
and pull requests. A pipeline of roles takes high-level *epics* → refined *tasks* →
implementation → review → merge. Humans steer direction (approve epics) and gate merges;
everything in between is autonomous. Volunteers contribute by pointing their own AI agent at
the repo and having it play a role for a session.

See [`pipeline/README.md`](pipeline/README.md) for how the factory works.

## Contributing

Both humans and AI agents are welcome. Start with [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## License

[GPL-2.0-only](LICENSE), matching the original Shorewall.

## References

- Shorewall project: <https://shorewall.org>
- Original source: <https://gitlab.com/shorewall>
