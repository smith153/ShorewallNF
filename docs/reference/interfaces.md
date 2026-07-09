# interfaces

The `interfaces` file binds network **devices** to the [zones](zones.md) they belong to, and
records per-interface options. It is processed after `zones`, so every zone it references must
already be declared there.

Each non-blank, non-comment line is one interface:

```
ZONE  INTERFACE  [BROADCAST]  OPTIONS      # FORMAT 1 (default)
ZONE  INTERFACE  OPTIONS                   # FORMAT 2
```

The file is a plain [tabular config file](config-files.md) (`#` comments, blank lines, and
trailing-`\` continuation are handled by the common reader, and `params` / `?if` preprocessing
applies).

## Columns

| Column | Required | Description |
|--------|----------|-------------|
| `ZONE` | yes | A zone name declared in [`zones`](zones.md), or `-` for a device in no zone. |
| `INTERFACE` | yes | The device name (e.g. `eth0`, `ppp0`). |
| `BROADCAST` | FORMAT 1 only | The broadcast column. Present but **currently ignored** — usually written as `detect`. Dropped entirely in FORMAT 2. |
| `OPTIONS` | no | A comma-separated list of interface options (see below). |

### `ZONE`

- A zone name that must exist in [`zones`](zones.md); an unknown zone fails fast.
- `-` marks a device that belongs to **no** zone (Shorewall's convention, e.g. an `ifb`
  redirect device). Such a row still registers the interface but attaches no membership.

### Zone membership

Every row with a real zone attaches the device to that zone as a **dual-stack** member — the
zone gains that interface for both IPv4 and IPv6. Multiple rows populate their respective
zones independently, and the firewall zone (declared `firewall` in `zones`) never gains
interface members. Host- or address-based membership is not expressed here (it is not part of
the `interfaces` file).

### `OPTIONS`

Options are given as a single comma-separated token (no spaces), e.g. `tcpflags,dhcp,nosmurfs`.

!!! warning "Options are recorded but not yet enforced"
    The options column is parsed and stored verbatim, but ShorewallNF does **not** yet act on
    any interface option — no option changes the generated ruleset today, and option names are
    not validated. The column is accepted for forward compatibility; treat any behavioral
    effect as not-yet-implemented.

## `?FORMAT` directive

A `?FORMAT n` line selects the column layout for the interface rows that follow it:

| `?FORMAT` | Layout | `OPTIONS` column |
|-----------|--------|------------------|
| `1` (default when no `?FORMAT` is given) | `ZONE INTERFACE BROADCAST OPTIONS` | 4th |
| `2` | `ZONE INTERFACE OPTIONS` | 3rd |

Any other value (e.g. `?FORMAT 3`) fails fast. The directive itself is not an interface entry.
Other directive rows such as `?SECTION` are ignored by this file.

## Validation

Parsing fails fast with a `file:line` error when:

- a line is missing the `INTERFACE` column;
- `ZONE` names a zone not declared in [`zones`](zones.md) (and is not `-`);
- a `?FORMAT` other than `1` or `2` is requested.

## Examples

FORMAT 1 (the default) — the `detect` in the third column is the ignored BROADCAST value, so
options are the fourth column:

```
#ZONE   INTERFACE   BROADCAST   OPTIONS
net     eth0        detect      tcpflags,dhcp,nosmurfs
loc     eth1        detect
-       ifb0                             # no zone: registered, no membership
```

FORMAT 2 — no BROADCAST column, so options move to the third column:

```
?FORMAT 2
#ZONE   INTERFACE   OPTIONS
net     eth0        tcpflags,dhcp
loc     eth1
```
