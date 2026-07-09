# `mangle`

The `mangle` file marks packets and steers transparent-proxy traffic. Its rows lower into a
single `prerouting` chain that runs **before the routing decision**, so a mark set here can drive
policy routing (a [`providers`](config-files.md) `ip rule` selects a routing table by fwmark) and
so `TPROXY`/`DIVERT` — which are only valid at `prerouting` — have a home
([ADR-0042](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0042-mangle-compilation.md)).

## Row format

Each non-comment row has up to five whitespace-separated columns:

```
#ACTION               SOURCE                DEST   PROTO   DPORT
CONNMARK(0x2/0xff)    net:198.51.100.0/24   -      tcp     80
MARK(0x1)             net                   -      tcp     443
DIVERT                net                   -      tcp     -
TPROXY(50080)         net:198.51.100.0/24   -      tcp     80
```

| Column | Required | Meaning |
|--------|----------|---------|
| `ACTION` | yes | The mark/proxy target — see [Actions](#actions). |
| `SOURCE` | no | `-` or a `zone` / `zone:host` source-match token. |
| `DEST` | no | `-` or a host-literal destination match. **Not** a bare zone (see below). |
| `PROTO` | no | Protocol to match (e.g. `tcp`, `udp`). |
| `DPORT` | no | Destination port(s) to match. |

Row order is preserved — it matters, since these are non-terminal rules evaluated top-to-bottom.
A sixth column or beyond is rejected.

!!! warning "No destination *zone* at prerouting"
    The routing decision has not run yet at `prerouting`, so there is no output interface. A rule
    can match the **source** zone (`iifname`), source/dest **host literals**, and proto/ports —
    but a destination expressed as a bare zone cannot be resolved here
    ([ADR-0042](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0042-mangle-compilation.md)).

## Actions

### `MARK(<value>[/<mask>])`

Set the **packet** mark to `<value>`, optionally under `<mask>`. `<value>` (and `<mask>`, if
given) are integers — decimal or `0x` hex. A missing value (`MARK()`) is rejected.

```
#ACTION       SOURCE   DEST   PROTO   DPORT
MARK(0x1)     net      -      tcp     443
MARK(1/0xff)  net      -      -       -
```

### `CONNMARK(<value>[/<mask>])`

Same syntax as `MARK`, but sets the **connection** mark — so the mark is observable on every
packet of the flow, not just the one matched.

```
#ACTION              SOURCE                DEST   PROTO   DPORT
CONNMARK(0x2/0xff)   net:198.51.100.0/24   -      tcp     80
```

### `DIVERT`

Keep an already-established transparent-proxy flow local — matched **before** `TPROXY` so
established packets are diverted to the local socket rather than re-redirected. Takes no
parameter.

```
#ACTION   SOURCE   DEST   PROTO   DPORT
DIVERT    net      -      tcp     -
```

### `TPROXY(<port>)`

Redirect a new connection to the local transparent-proxy listener on `<port>` (1–65535). The
mark is **not** written per-rule: the generator injects the reserved `TPROXY_MARK`
(`0xFFFFFFFF`), shared with `DIVERT`, so one `ip rule fwmark` delivers both new and established
packets to the local stack
([ADR-0051](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0051-transparent-proxy-mark-and-local-delivery-routing.md)).

!!! warning "TPROXY takes no per-rule mark"
    `TPROXY(<port>,<mark>)` is **rejected**, not silently accepted. The tproxy mark is the
    reserved constant the generator manages, not an operator value — use `TPROXY(<port>)`.

## Family

A row's family is inferred from its content (`SOURCE`/`DEST` host literals, `PROTO`); a
family-scoped rule compiles with a `meta nfproto` guard, and a `TPROXY` lowers to the concrete
`tproxy ip` / `tproxy ip6` for its family in the `inet` table
([ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)).

## Worked example — transparent proxy

The canonical tproxy ordering: stamp the connection, divert established flows, then redirect new
ones to the proxy port. Documentation ranges only (RFC 5737).

```
#ACTION               SOURCE                DEST   PROTO   DPORT
CONNMARK(0x2/0xff)    net:198.51.100.0/24   -      tcp     80
DIVERT                net                   -      tcp     -
TPROXY(50080)         net:198.51.100.0/24   -      tcp     80
```

## What it compiles to

The generator emits one `prerouting` mangle chain in the `inet filter` table
(`priority mangle` = -150, `policy accept`, ahead of the nat `dstnat` chain and the routing
decision), only when any `mangle` rule exists. Each row lowers to a rule with its match criteria
followed by the target: `meta mark set` / `ct mark set` for `MARK`/`CONNMARK`, the
`socket transparent` + shared-mark accept for `DIVERT`, and `tproxy to :<port>` + shared-mark
accept for `TPROXY`
([ADR-0042](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0042-mangle-compilation.md),
[ADR-0051](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0051-transparent-proxy-mark-and-local-delivery-routing.md)).

## See also

- [`providers`](config-files.md) — policy-routing providers that consume fwmarks.
- [ADR-0042 — Mangle compilation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0042-mangle-compilation.md)
- [ADR-0051 — Transparent-proxy mark reservation + local-delivery routing](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0051-transparent-proxy-mark-and-local-delivery-routing.md)
