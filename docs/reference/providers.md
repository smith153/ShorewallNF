# providers

The `providers` file declares **policy-routing providers**: a packet carrying a provider's
firewall mark (fwmark) is routed out that provider's interface via its gateway. That routing
decision is made by the **Linux routing subsystem** (`ip rule` + a per-provider routing table),
not by nftables — nftables only *carries* the mark ([ADR-0050](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0050-policy-routing-artifact-model.md)).
Each provider row therefore compiles to a routing artifact, not to an nftables rule.

## Row format

```
NAME  NUMBER  MARK  INTERFACE  GATEWAY  [OPTIONS]
```

Columns are whitespace-separated. File order is preserved. The first five columns are
required; `OPTIONS` is optional. A missing required column, a non-integer `NUMBER`/`MARK`, or a
seventh column fails fast with a `file:line` error.

| Column | Required | Accepted values |
|--------|----------|-----------------|
| `NAME` | yes | The provider label (an arbitrary token used to identify the provider). |
| `NUMBER` | yes | The routing-table id — an integer, decimal (`1`) or `0x` hex (`0x1`). |
| `MARK` | yes | The fwmark steered into that table — an integer, decimal or `0x` hex. |
| `INTERFACE` | yes | The egress interface name (e.g. `eth0`). |
| `GATEWAY` | yes | The next-hop: an IPv4/IPv6 address literal, or a non-literal such as `detect`. |
| `OPTIONS` | no | A comma-separated list of option tokens, preserved verbatim. |

### Family

A provider's family follows its **gateway** ([ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)):

- an IPv4 gateway literal scopes the provider to IPv4,
- an IPv6 gateway literal scopes it to IPv6,
- a non-literal gateway (e.g. `detect`) leaves it dual-stack.

A routing table is single-family, so a provider that reaches the generator with a non-address
gateway is rejected: give the provider a literal gateway address.

### OPTIONS

`OPTIONS` is accepted and preserved verbatim as a comma-separated list. The routing generator
currently derives the artifact from `NUMBER`, `MARK`, `GATEWAY`, and `INTERFACE` only; option
tokens are not yet interpreted.

## What it compiles to

Each row yields, for its family:

- a **routing table** whose id is `NUMBER`, with a default route via `GATEWAY` on `INTERFACE`;
- an **fwmark → table selection rule** (`ip rule`) matching `MARK`.

The mark itself is set elsewhere (the `mangle` file); providers only *consume* it.

## Examples

A single IPv4 provider — table `1`, fwmark `0x1`, out `eth0` via a documentation-range gateway:

```
#NAME   NUMBER  MARK   INTERFACE  GATEWAY
isp1    1       0x1    eth0       192.0.2.1
```

Two providers for a dual-uplink setup (one per uplink), IPv4:

```
#NAME   NUMBER  MARK   INTERFACE  GATEWAY
isp1    1       0x1    eth0       192.0.2.1
isp2    2       0x2    eth1       198.51.100.1
```

An IPv6 provider — its gateway literal scopes it to IPv6:

```
#NAME   NUMBER  MARK   INTERFACE  GATEWAY
isp6    3       0x3    eth0       2001:db8::1
```
