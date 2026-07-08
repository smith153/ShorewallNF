# zones

The `zones` file declares the named network **zones** your policy and rules refer to. It is
processed before `interfaces` so that file can bind devices to the zones defined here.

Each non-blank, non-comment line is one zone:

```
ZONE  TYPE
```

Only the first two columns are read; the file is otherwise a plain
[tabular config file](config-files.md) (`#` comments, blank lines, and trailing-`\`
continuation are handled by the common reader, and `params` / `?if` preprocessing applies).

## Columns

| Column | Required | Description |
|--------|----------|-------------|
| `ZONE` | yes | The zone name, used everywhere else (`interfaces`, `policy`, `rules`, …). Names are family-independent. |
| `TYPE` | yes | One of `ipv4`, `ipv6`, or `firewall`. |

### `TYPE` values

| Value | Meaning |
|-------|---------|
| `ipv4` | An ordinary network zone. |
| `ipv6` | An ordinary network zone. |
| `firewall` | The firewall host itself (Shorewall's `$FW`). Marks this as the firewall zone; it has no interface members. |

!!! note "Address family lives on membership, not the zone (ADR-0002)"
    ShorewallNF models one dual-stack `inet` ruleset, so a zone has a single,
    family-independent identity. The `ipv4` and `ipv6` type keywords are both accepted for an
    ordinary zone and produce the **same** zone — the family is not stored on the zone. A
    zone's effective family emerges from its members (see [`interfaces`](interfaces.md)): a
    zone bound only to interfaces is dual-stack. Use `firewall` only to mark the single
    firewall zone.

## Membership

The `zones` file names zones but does not populate them. Interface membership is attached by
the [`interfaces`](interfaces.md) file, which references the zone names declared here. The
`firewall` zone has no interface members.

## Validation

Parsing fails fast with a `file:line` error when:

- a line is missing the `ZONE` or `TYPE` column;
- `TYPE` is not one of `ipv4`, `ipv6`, `firewall`;
- a zone name is declared more than once (duplicate).

A zone referenced by `interfaces`, `policy`, or `rules` but never declared here is rejected by
those files as an unknown zone.

## Examples

A firewall zone plus three ordinary zones:

```
#ZONE   TYPE
fw      firewall
net     ipv4
loc     ipv4
dmz     ipv4
```

The `ipv4`/`ipv6` keyword does not fix the zone's family: `guest ipv4` and `guest ipv6` declare
the *same* zone, and whether `guest` carries IPv4, IPv6, or both is decided by the interfaces
bound to it. (A zone name may appear only once — declaring `guest` twice is a duplicate-zone
error, not a way to add both families.)
