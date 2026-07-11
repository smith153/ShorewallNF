# `policy`

The `policy` file sets the **default action** for traffic between zones — the verdict applied
to a connection that no more-specific `rules`-file entry has already accepted. It is the
fail-closed backstop of the filtering core.

Each non-comment line is one policy:

```text
#SOURCE  DEST  ACTION  [LOG LEVEL]  [LIMIT:BURST]
```

Columns are whitespace-separated. Blank lines and `#` comments (whole-line or trailing) are
ignored. The file is [preprocessed](config-files.md#preprocessing) first, so `params`
substitution and `?if`/`?FORMAT` directives apply.

## Columns

| Column | Index | Required | Value |
|--------|-------|----------|-------|
| `SOURCE` | 0 | yes | A declared zone, the firewall zone, or the wildcard `all`. |
| `DEST` | 1 | yes | A declared zone, the firewall zone, or the wildcard `all`. |
| `ACTION` | 2 | yes | `ACCEPT`, `DROP`, or `REJECT`. |
| `LOG LEVEL` | 3 | no | An nftables log level — logs the connection before applying the verdict. |
| `LIMIT:BURST` | 4 | no | `<rate>/<interval>[:<burst>]` — rate-limits *new* connections the policy defaults (see [`LIMIT:BURST`](#limitburst) below). |

A line with fewer than three columns, an unknown zone, an unknown action, an unsupported log
level, or **any sixth column** is a hard error: the compiler stops with a `file:line` message
rather than guess. Shorewall's `CONNLIMIT` column is not implemented, so it is rejected rather
than silently dropped.

### `SOURCE` / `DEST`

Zone names must already be declared in the [`zones`](config-files.md) file (the firewall zone
included). `all` is the wildcard zone. Zones are matched **by interface**: the source zone
matches on `iifname`, the destination zone on `oifname`, against the interface(s) bound to that
zone in the [`interfaces`](config-files.md) file. The firewall zone and `all` contribute no
interface match — the firewall zone is the host itself, and `all` is a wildcard — so an
`all all` policy compiles to a bare verdict.

A policy that names a normal zone with **no interfaces** cannot be matched and is a hard error
(fail-closed) rather than an empty match.

### `ACTION`

| Action | nftables verdict |
|--------|------------------|
| `ACCEPT` | `accept` |
| `DROP` | `drop` (silently discard) |
| `REJECT` | `reject` (discard and send an ICMP/RST error) |

### `LOG LEVEL`

When present, the compiler emits an nftables `log level <lvl>` statement immediately before the
verdict. Accepted levels are the nftables (syslog) keywords plus `audit`:

```
emerg  alert  crit  err  warn  notice  info  debug  audit
```

Shorewall's alternate syslog spellings (`warning`, `error`, `panic`), numeric levels, and
`NFLOG`/`ULOG` targets are **not** accepted — an unsupported level is a hard error. No log
prefix is emitted, and `REJECT` logging is not distinguished from `DROP`/`ACCEPT` logging.

### `LIMIT:BURST`

`<rate>/<interval>[:<burst>]` — the same rate-spec grammar as the `rules` file's
[`RATE LIMIT`](rules.md#rate-limit-and-connlimit) column:

| Field | Value |
|-------|-------|
| `rate` | A positive integer. |
| `interval` | One of `sec`, `min`, `hour`, `day` (maps to nftables' `second`/`minute`/`hour`/`day`). |
| `burst` | Optional positive integer packet-burst allowance; nftables' default applies when omitted. |

When present, the compiler emits an nftables `limit rate` statement on the policy rule itself,
immediately before the verdict — rate-limiting the *new* connections that reach the policy
fall-through (traffic a `rules`-file entry hasn't already matched). Over-rate new connections
fall through past the policy to the chain's built-in default (see
[Implicit defaults](#implicit-defaults)). Shorewall's named/shared limiters (a name or `s:`/`d:`
selector before the rate) are **not implemented** and are rejected. The policy `CONNLIMIT`
column is **not implemented**.

## How policies compile

Each policy becomes one rule appended to a base filter chain, after the always-on stateful and
loopback accepts and after any `rules`-file entries, so it is the last thing evaluated in the
chain.

**Chain selection** follows the role of the firewall zone:

| Policy | Chain |
|--------|-------|
| `DEST` is the firewall zone | `input` (traffic to the firewall host) |
| `SOURCE` is the firewall zone | `output` (traffic from the firewall host) |
| neither side is the firewall zone | `forward` (inter-zone forwarded traffic) |

Source-firewall takes precedence, so a degenerate `$fw $fw` policy lands in `output`.

**Ordering** is by specificity, not file order: a specific zone pair is emitted first, a policy
with one `all` side next, and `all all` last. This keeps a specific pair from being shadowed by
a wildcard catch-all. Within one specificity tier, file order is preserved.

!!! warning "`all all` is the inter-zone catch-all, not a universal default"
    Because `all all` has neither side as the firewall zone, it compiles to a `forward` rule
    **only** — it does not govern traffic to or from the firewall host. Consequences worth
    noting:

    - `all all DROP` is harmless (the `input` base chain already drops).
    - `all all REJECT` leaves firewall-bound traffic *dropped* rather than rejected.
    - `all all ACCEPT` does **not** open the firewall host — `input` stays closed.

    A config that wants firewall-host defaults writes explicit `$fw`/`→ $fw` policies. This is a
    deliberate divergence from Shorewall's universal `all all`.

### Implicit defaults

You do not have to write a policy for every chain. Absent any matching policy, the base filter
chains fall back to their built-in verdicts — `input drop`, `forward drop`, `output accept` —
and the always-on rules accept established/related connections and loopback traffic. The result
is fail-closed inbound and forwarded traffic with outbound allowed.

## Example

A small three-zone setup — a WAN zone `net`, a LAN zone `loc`, and the firewall zone `fw`:

```text
#SOURCE  DEST  ACTION  LOG LEVEL  LIMIT:BURST
loc      net   ACCEPT  -          100/sec:20
loc      fw    ACCEPT
fw       net   ACCEPT
net      all   DROP    info
all      all   REJECT  info
```

This allows the LAN out to the internet, capped at 100 new connections/second (burst 20); lets
the LAN reach the firewall host and the firewall reach the internet; logs-and-drops everything
arriving from `net`; and logs-and-rejects any remaining inter-zone traffic. More specific rows
are evaluated before the `all` catch-alls regardless of the order written.

## Inspecting compiled policies

`shorewallnf show policies <config_dir>` renders the inter-zone default-policy matrix —
`SOURCE -> DEST -> ACTION`, plus the log level when one is set (`-` when not). Because policies
are a compile-time declaration and not recoverable from live nft state, this verb reads the
**config directory** (unlike `show rules`, which reads the running kernel). `list`/`ls` are exact
synonyms; it is read-only.

```
$ shorewallnf show policies /etc/shorewallnf
Policies

  SOURCE  DEST  ACTION  LOG
  loc     net   ACCEPT  -
  net     all   DROP    info
  all     all   REJECT  -
```

Rows are shown in file order (the specificity re-ordering above is a compile-time concern). A
valid config that declares no policies renders an empty-but-valid section.

## See also

- [`rules`](rules.md) — per-connection rules and DNAT, evaluated **before** these defaults.
- [`zones` / `interfaces`](config-files.md) — where zones and their interfaces are declared.
