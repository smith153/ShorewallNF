# sets

The `sets` file **declares named sets** — the address collections a `rules` `SOURCE`/`DEST`
column references as `+setname` (see [named-set matching](rules.md#setname-named-set-matching)).
A declaration fixes a set's name, address family, and element type; the compiler emits the
matching, self-contained nftables `set` object so a `+setname` match resolves
([ADR-0066](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0066-named-sets.md)).

Declaring a set here does **not** populate it — runtime membership (adding/removing addresses,
e.g. a dynamic blacklist) is a separate concern and out of scope for the compiler; the emitted
objects start empty.

## Row format

```
NAME  FAMILY  TYPE
```

Columns are whitespace-separated. All three are required; a missing column or an unknown
`FAMILY`/`TYPE` value fails fast with a `file:line` error.

| Column | Accepted values | Meaning |
|--------|-----------------|---------|
| `NAME` | an identifier | the set's name, referenced as `+NAME` in `rules` |
| `FAMILY` | `ipv4`, `ipv6`, `both` | the address family the set holds |
| `TYPE` | `address`, `address:port` | element kind — a bare address, or an address+port pair |

Example:

```
#NAME       FAMILY   TYPE
goodguys    ipv4     address
web         both     address
blocklist   ipv6     address
```

## How a declared set is matched and emitted

A `+setname` in a `rules` `SOURCE`/`DEST` column becomes an nftables set-membership match
(`ip saddr @setname` / `ip6 daddr @setname`; `!+setname` emits the negated `!=` form). Only an
`address` set matches as a bare `SOURCE`/`DEST` host term; an `address:port` set referenced there
is a hard error (address+port matching is not yet lowered).

The set's declared `FAMILY` scopes the referencing rule exactly as an address literal does — an
`ipv4` set narrows the rule to IPv4, an `ipv6` set to IPv6, and a `both` set leaves it dual-stack.

### Hard errors

- **Undeclared set** — a `+setname` reference to a set not declared here fails fast.
- **Family conflict** — a single-family set met by an opposite-family literal or protocol on the
  rule (e.g. an `ipv4` set with an `ipv6-icmp` proto, or against a `2001:db8::/32` host on the
  other side) fails fast, exactly like two mismatched address literals.

## `both`-family sets → two nft objects (naming contract)

An nftables named set in the unified `inet` table is **single-typed** — its elements are all
`ipv4_addr` **or** all `ipv6_addr`; there is no dual-family set object. A set declared `both`
therefore compiles to **two** objects, one per family, with a fixed suffix naming contract:

| Declared set (`both`) | Emitted objects | Referenced from |
|-----------------------|-----------------|-----------------|
| `web` | `web_v4` (`type ipv4_addr`), `web_v6` (`type ipv6_addr`) | the rule's IPv4 arm uses `@web_v4`, its IPv6 arm `@web_v6` |

A single-family set keeps its bare name: an `ipv4` set `goodguys` emits one `goodguys`
(`type ipv4_addr`) object referenced as `@goodguys`; an `ipv6` set likewise. A `both`-family
rule (`+web` with no other family constraint) splits into a v4 arm matching `@web_v4` and a v6 arm
matching `@web_v6`, mirroring the per-family split a `both` ICMP rule already performs
([ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)).

This `NAME_v4` / `NAME_v6` naming is the contract runtime set population (the blacklist epic)
populates against.
