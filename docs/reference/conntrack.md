# `conntrack`

The `conntrack` file attaches **connection-tracking application helpers** to flows. Protocols
that open secondary data connections — FTP data channels, SIP/RTP media, the GRE tunnel of PPTP
— need a kernel helper so the related traffic is tracked as `RELATED` and admitted by the
existing policy. Each row assigns one built-in helper to the connections a source/dest scope
selects.

!!! note "Scope of the current implementation"
    Only helper *assignment* (`CT:helper:<name>`) is supported. Shorewall's `notrack` /
    raw-table exemptions are out of scope; a row with any other action is rejected. Helpers come
    from a fixed built-in registry (below) — an unknown name fails fast
    ([ADR-0040](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0040-conntrack-helper-ir-and-registry.md)).

## Row format

Each non-comment row has up to five whitespace-separated columns:

```
#ACTION            SOURCE   DEST                 PROTO   DPORT
CT:helper:ftp      net      loc:198.51.100.10    tcp     21
CT:helper:tftp     net      loc
CT:helper:pptp     net      loc
```

| Column | Required | Meaning |
|--------|----------|---------|
| `ACTION` | yes | `CT:helper:<name>` — the built-in helper to attach (see [Helpers](#built-in-helpers)). |
| `SOURCE` | no | `-` (unspecified) or a `zone` / `zone:host` narrowing token for the source. |
| `DEST` | no | `-` (unspecified) or a `zone` / `zone:host` narrowing token for the destination. |
| `PROTO` | no | Overrides the helper's default protocol. Lower-cased. |
| `DPORT` | no | Overrides the helper's default destination port(s). |

A column left as `-` is unspecified. `PROTO` and `DPORT` default to the helper's registry values
when omitted. A sixth column or beyond is rejected.

### `SOURCE` / `DEST` zones

A zone token is a zone name, optionally narrowed to a host with `zone:host`. The zone part must
be a **declared zone** (from the [`zones`](config-files.md) file) or the special `all`; an
unknown zone fails fast. A host literal also narrows the row's **family**: an IPv4 literal scopes
the row to IPv4, an IPv6 literal to IPv6.

## Built-in helpers

The registry is a fixed, documented set (only what the project needs — an unknown name is
detectable). Each helper has a canonical protocol, default port, and **family capability**:

| `<name>` | Proto | Default port | Family capability |
|----------|-------|--------------|-------------------|
| `ftp`  | tcp | 21   | IPv4 + IPv6 |
| `tftp` | udp | 69   | IPv4 + IPv6 |
| `sip`  | udp | 5060 | IPv4 + IPv6 |
| `pptp` | tcp | 1723 | IPv4 only (its GRE pairing has no IPv6 conntrack support) |

### Family resolution

A row's family is the helper's capability, **narrowed** by any host literal in `SOURCE`/`DEST`.
Assigning a v4-capable-and-v6-capable helper with no literal leaves the row dual-stack. A literal
that **conflicts** with the capability — e.g. an IPv6 host on the IPv4-only `pptp` — is rejected
rather than emitting a rule the kernel would refuse
([ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)).

## Examples

Attach the FTP helper to inbound FTP, narrowed to one internal host (which scopes it to IPv4):

```
#ACTION          SOURCE   DEST                 PROTO   DPORT
CT:helper:ftp    net      loc:198.51.100.10    tcp     21
```

Attach the TFTP helper dual-stack (no literal, so it stays IPv4 + IPv6), using registry defaults
for proto/port:

```
#ACTION          SOURCE   DEST
CT:helper:tftp   net      loc
```

## What it compiles to

The generator emits **one `ct helper` object per distinct helper name** in the `inet filter`
table, deduplicated across rows, with its `l3proto` from the capability — `inet` for a
v6-capable helper (one object serving both families), `ip` for a v4-only helper — followed by the
per-row assignment rules (`… ct helper set "<name>"`) in the family-correct chain. A helper the
running platform does not provide is **skipped**, not emitted (Shorewall's `AUTOHELPERS` gate)
([ADR-0041](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0041-conntrack-helper-compilation.md)).

## See also

- [ADR-0040 — Conntrack helper IR model + built-in registry](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0040-conntrack-helper-ir-and-registry.md)
- [ADR-0041 — Conntrack helper compilation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0041-conntrack-helper-compilation.md)
