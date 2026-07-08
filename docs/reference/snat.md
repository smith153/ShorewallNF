# `snat`

The `snat` file declares **source NAT** — rewriting the *source* address of outbound
connections, either dynamically to the egress interface's address (`MASQUERADE`) or statically
to a fixed address (`SNAT`). It is the counterpart to the `DNAT` port-forwards in the
[`rules`](config-files.md) file.

!!! info "IPv4 only"
    Source NAT is IPv4-only by construction. IPv6 does no NAT — a global IPv6 host keeps its
    own address — so every `snat` row is scoped to IPv4 regardless of content
    ([ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md),
    [ADR-0009](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0009-snat-compilation.md)).

## Row format

Each non-comment row has three whitespace-separated columns, in order:

```
#ACTION            SOURCE                 DEST
MASQUERADE         10.0.0.0/8             eth0
SNAT(203.0.113.5)  192.0.2.0/24           eth1
```

| Column | Required | Meaning |
|--------|----------|---------|
| `ACTION` | yes | `MASQUERADE` or `SNAT(<addr>)` — see [Actions](#actions). |
| `SOURCE` | yes | The source network(s) to translate — a single CIDR or a comma-separated list, stored verbatim and expanded by the generator. |
| `DEST` | yes | The **egress (out) interface** the translated traffic leaves by. |

All three columns are mandatory; a row missing any of them fails fast with a located error.

!!! warning "Narrowing columns are out of scope"
    Shorewall's further `snat` columns (`PROTO`, `PORT`, `IPSEC`, `MARK`, `PROBABILITY`) are
    **not** yet supported. A row that carries a fourth column or beyond is rejected rather than
    silently dropped, so no rule ever translates more than what is written.

## Actions

### `MASQUERADE`

Dynamic source NAT to the egress interface's current address — the right choice when that
address is assigned dynamically (DHCP, PPPoE). Carries no address parameter.

```
#ACTION      SOURCE       DEST
MASQUERADE   10.0.0.0/8   eth0
```

### `SNAT(<addr>)`

Static source NAT to the explicit address `<addr>` — use when the egress interface has a stable
address you want as the visible source. The address is required: a bare `SNAT` or an empty
`SNAT()` is rejected.

```
#ACTION             SOURCE         DEST
SNAT(203.0.113.5)   192.0.2.0/24   eth1
```

## Multiple source networks

`SOURCE` may be a comma-separated list; the whole list is translated by the one row.

```
#ACTION      SOURCE                                        DEST
MASQUERADE   10.0.0.0/8,192.0.2.0/24,203.0.113.0/24        eth0
```

## What it compiles to

A `MASQUERADE`/`SNAT` row compiles to a rule in the `inet nat` table's `postrouting` chain
(source-NAT priority): an `oifname` match on the egress interface, then the source-address
narrowing, then the translation (`masquerade`, or `snat to <addr>`). Source NAT only rewrites
the source of a connection the `forward` policy already admits — it opens nothing, so, unlike a
`DNAT`, it adds no `forward` accept
([ADR-0009](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0009-snat-compilation.md)).

## See also

- [`rules`](config-files.md) — `DNAT` port-forwarding (destination NAT).
- [ADR-0008 — NAT table skeleton + DNAT compilation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0008-nat-compilation.md)
- [ADR-0009 — SNAT/MASQUERADE compilation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0009-snat-compilation.md)
