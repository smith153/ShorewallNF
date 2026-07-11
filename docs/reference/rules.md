# `rules`

The `rules` file holds **per-connection** rules — the explicit exceptions evaluated *before* the
[`policy`](policy.md) defaults. It carries two kinds of entry:

- **filter rules** — accept, drop, or reject a specific class of connection;
- **`DNAT` rules** — port-forward an inbound connection to an internal host.

Each non-comment line is one entry; columns are whitespace-separated; blank lines and `#`
comments are ignored. The file is [preprocessed](config-files.md#preprocessing) first, so
`params` substitution and the `?if`/`?FORMAT`/`?SECTION` directives apply. A `-` in any optional
column means "unspecified".

## Filter rules

```text
#ACTION  SOURCE  DEST  [PROTO]  [DEST PORT]  [SOURCE PORT]
```

| Column | Required | Value |
|--------|----------|-------|
| `ACTION` | yes | A built-in verdict (`ACCEPT`/`DROP`/`REJECT`) or a macro/action name (see [Actions](#actions-and-macros)). |
| `SOURCE` | yes | `zone` or `zone:host` — the originating zone, optionally narrowed to a host/CIDR. |
| `DEST` | yes | `zone` or `zone:host` — the destination zone, optionally narrowed to a host/CIDR. |
| `PROTO` | no | `tcp`, `udp`, `icmp`, or `ipv6-icmp` (case-insensitive). |
| `DEST PORT` | no | Destination port(s). Requires a `PROTO`. |
| `SOURCE PORT` | no | Source port(s). Requires a `PROTO`. |

Any **seventh column** is a hard error — Shorewall's `ORIGINAL DEST` / `RATE LIMIT` /
`USER-GROUP` / `MARK` columns are not implemented yet and are rejected rather than silently
dropped.

Filter rules are placed **ahead of** the policy defaults in the same base chain, so an explicit
verdict wins over the zone-pair default. Chain selection and interface-based zone matching are
identical to [`policy`](policy.md#how-policies-compile): source firewall zone → `output`, dest
firewall zone → `input`, else `forward`.

### `SOURCE` / `DEST` and `zone:host` narrowing

The bare `zone` form matches by interface, exactly as a policy does. The `zone:host` form adds an
address match — a source host narrows on `saddr`, a destination host on `daddr`. `host` is an
IPv4/IPv6 address or a CIDR (`192.0.2.0/24`, `2001:db8::5`). The literal's family determines the
match (`ip` vs `ip6`) and is itself the family guard — no extra family match is added.

### `+setname` — named-set matching

A `SOURCE` or `DEST` column may be a **named-set reference** instead of a zone: `+setname` matches
any host in the declared set `setname`, and `!+setname` matches any host **not** in it. The set
must be declared in the `sets` file, which fixes its address family (`ipv4`/`ipv6`/`both`):

```
#ACTION   SOURCE       DEST   PROTO   DEST PORT
ACCEPT    +goodguys    fw     tcp     22
DROP      !+goodguys   fw
ACCEPT    net          +web   tcp     443
```

The set's declared family scopes the rule the same way an address literal does: a `ipv4`-only set
narrows the rule to IPv4, an `ipv6`-only set to IPv6, and a `both` set leaves it dual-stack. A set
referenced against a conflicting family — an `ipv4` set with `ipv6-icmp`, or against a
`2001:db8::/32` host on the other side — is a hard error, as is a reference to a set that was never
declared.

### `PROTO` and ports

`PROTO` is stored in nftables' canonical lowercase. A port column **requires** a protocol; a port
without a proto is a hard error.

| Port form | Example | Compiles to |
|-----------|---------|-------------|
| single | `22` | a scalar match |
| list | `80,443` | an anonymous set `{ 80, 443 }` |
| range | `8000:8100` | a range `8000-8100` |

A list element may itself be a range, and a non-numeric token (a service name like `ssh`) passes
through verbatim for nftables to resolve. With ports, one payload match is emitted per column
(`dport` before `sport`) and no separate protocol match — nftables folds the protocol dependency
back in on load.

`icmp` pins a rule to IPv4 and `ipv6-icmp` to IPv6 (with an ICMP type such as `echo-request` in
the `DEST PORT` column). A rule that mixes IPv4 and IPv6 hints — say an IPv4 host on one side and
`ipv6-icmp` — is a hard error.

### Actions and macros

The `ACTION` column is either a built-in verdict or the name of a macro/action, resolved before
validation:

- Built-in verdicts: `ACCEPT` → `accept`, `DROP` → `drop`, `REJECT` → `reject`.
- Built-in macros/actions: `Web` (accept inbound TCP 80 and 443) and `DropSmb` (silently drop
  SMB/NetBIOS chatter on UDP 137–139/445 and TCP 139/445).
- Site definitions: an `action.<Name>` file in the config directory defines a custom action;
  its name may then be used in the `ACTION` column. A site definition overrides a built-in of
  the same name.

A macro/action expands to one rule per body line, each narrowed by the call site's
source/dest/proto/ports. An unknown action name, or a narrowing whose port/proto intersection is
empty, is a hard error citing the offending line.

### `?SECTION` — connection-state ordering

A `?SECTION <NAME>` directive on its own line sets the connection-state section for the filter
rules that follow. The recognized names, and the order rules are emitted in regardless of where
they appear in the file, are:

| Section | Matches | Notes |
|---------|---------|-------|
| `ESTABLISHED` | `ct state established` | `ACCEPT`-only (see below). |
| `RELATED` | `ct state related` | `ACCEPT`-only (see below). |
| `INVALID` | `ct state invalid` | |
| `NEW` | new connections | The default for a rule written before any `?SECTION`. |

Within a section, file order is preserved. An unrecognized section name is a hard error.

!!! note "ESTABLISHED / RELATED are accept-only"
    The base filter chains already fast-path `ct state {established, related} accept` at the top,
    so a `DROP` or `REJECT` in the `ESTABLISHED` or `RELATED` section would be unreachable. The
    validator rejects that dead case up front; an `ACCEPT` there is a redundant no-op.
    `INVALID` and `NEW` are unaffected.

### Filter example

```text
#ACTION            SOURCE            DEST   PROTO       DEST PORT
ACCEPT             net               fw     tcp         22
Web                net               fw
ACCEPT             loc               net    tcp         80,443
ACCEPT             loc:192.0.2.0/24  net    udp         53
ACCEPT             net               fw     icmp        echo-request
ACCEPT             net               fw     ipv6-icmp   echo-request
```

This accepts inbound SSH to the firewall, exposes a web service via the `Web` macro, lets the
LAN reach web and DNS out, and allows IPv4 and IPv6 ping to the firewall. Each rule is reached
before the `policy` defaults.

## DNAT / port-forwarding

A `DNAT` entry forwards an inbound connection to an internal host (a port-forward):

```text
DNAT  SOURCE  ZONE:HOST[:PORT]  [PROTO]  [DEST PORT]
```

| Column | Required | Value |
|--------|----------|-------|
| `DNAT` | yes | The literal action. |
| `SOURCE` | yes | The external zone (`zone`, or `all`). |
| `ZONE:HOST[:PORT]` | yes | Target: the internal `ZONE`, the internal `HOST` address, and an optional `:PORT` **remap**. |
| `PROTO` | no | `tcp`/`udp`/… |
| `DEST PORT` | no | The **external** port(s) matched on the way in. Requires a `PROTO`. |

The target column must include a host (`zone:host`) or it is a hard error. Any **sixth column**
is rejected. `?SECTION` does not apply to `DNAT` rows.

A v4 `DNAT` compiles to **two** rules:

1. a `nat` `prerouting` rule that matches the inbound interface and the external `DEST PORT`,
   then rewrites the destination to `HOST` (a `dnat` target);
2. a `filter` `forward` rule that admits the translated connection to `HOST` through the
   fail-closed forward chain (the `nat` rule alone would be dropped).

The dedicated `inet nat` table is emitted only when the config actually has NAT entries.

### The `:PORT` remap

An optional `:PORT` on the target **rewrites** the destination port. When present, the `dnat`
target and the forward accept use the *remapped* internal port, while `prerouting` still matches
the *external* `DEST PORT`. With no remap, the internal host is reached on the same external port.

### IPv6 targets take no NAT

NAT is IPv4-only. A `DNAT` whose target is an IPv6 literal does **no** translation: it compiles
to a plain `forward` `accept` to that global IPv6 address (a service is exposed by being globally
routable, not NATed). No `nat` table or `prerouting` rule is emitted for it.

### Port-forward example

Expose services on internal hosts, using documentation address ranges only:

```text
#ACTION  SOURCE  DEST                     PROTO   DEST PORT
DNAT     net     loc:192.0.2.10           tcp     80
DNAT     net     loc:198.51.100.20        tcp     8000:8100
DNAT     net     loc:203.0.113.30:8022    tcp     22
DNAT     net     loc:2001:db8::5          tcp     443
```

Reading top to bottom:

- inbound TCP 80 from `net` is forwarded to `192.0.2.10:80`;
- inbound TCP 8000–8100 is forwarded to `198.51.100.20` on the same range;
- inbound TCP 22 is forwarded to `203.0.113.30` and **remapped** to port 8022;
- inbound TCP 443 to the IPv6 host `2001:db8::5` is accepted directly (no NAT).

Each forward is admitted through the `forward` chain, so it works even though the default forward
policy is `drop`.

## See also

- [`policy`](policy.md) — the inter-zone defaults these rules are layered ahead of.
- [`snat`](config-files.md) — source NAT / masquerading (the outbound counterpart to `DNAT`).
- [`zones` / `interfaces`](config-files.md) — where zones and their interfaces are declared.
