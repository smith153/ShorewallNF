# Configuration files

ShorewallNF reads a **configuration directory** of Shorewall-style tabular files. It processes
only the files it knows about, in a fixed order; anything else in the directory is ignored.

!!! warning "Skeleton page"
    One row per file with a link out to a dedicated page as each is documented in full.

## Files ShorewallNF processes

| File | Purpose |
|------|---------|
| [`params`](params.md) | Variable definitions substituted into the other files during preprocessing. |
| `zones` | Named network zones (family-aware membership). |
| `interfaces` | Interface-to-zone bindings and per-interface options. |
| [`providers`](providers.md) | Policy-routing providers. |
| [`policy`](policy.md) | Default inter-zone policies and their logging. |
| [`rules`](rules.md) | Per-connection filter rules and DNAT/port-forwarding. |
| `snat` | Source NAT / masquerading (IPv4). |
| `conntrack` | Connection-tracking helper assignments (FTP, SIP, …). |
| `mangle` | Packet marking and `TPROXY`. |
| [`stoppedrules`](stoppedrules.md) | Admin-access rules that stay in force in the stopped safe state. |

A global settings file (`shorewallnf.conf`, an nftables-native subset of Shorewall's
`shorewall.conf`) is [planned](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0061-global-settings-file.md).

## Preprocessing

Before parsing, ShorewallNF resolves `params` substitution and the `?if` / `?FORMAT` /
`?SECTION` directives, so the files support the same conditional and formatting constructs as
Shorewall.
