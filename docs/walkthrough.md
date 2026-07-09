# Walkthrough: a two-interface router with a port-forward

This tutorial builds a small, complete firewall from an empty directory: a router with a
**WAN** and a **LAN** interface that forwards a public web port to an internal host and
masquerades outbound LAN traffic. You will write five config files, then drive them through the
`check` → `compile` → `apply` lifecycle.

All addresses below are from the documentation ranges (RFC 5737 / RFC 3849), so you can copy the
files verbatim without pointing at anything real.

!!! note "Prerequisites"
    Install the `shorewallnf` command first — see [Install (from source)](getting-started.md#install-from-source).
    `check` and `compile` run unprivileged anywhere; only `apply` touches the live ruleset and
    needs `sudo` on a real nftables host.

## What we're building

| Piece | Choice |
|-------|--------|
| **`net`** zone (WAN) | interface `eth0` |
| **`loc`** zone (LAN) | interface `eth1` |
| Default policy | LAN may reach the internet; everything else is dropped/rejected |
| Port-forward | inbound TCP 80 on the WAN → `192.0.2.10:80` on the LAN (DNAT) |
| Admin access | inbound TCP 22 to the firewall itself |
| Outbound NAT | masquerade the `192.0.2.0/24` LAN out `eth0` |

## Step 1 — create the config directory

```bash
mkdir router && cd router
```

Everything below lives in this directory. ShorewallNF only reads the files it recognises, in a
fixed order; see the [configuration file reference](reference/config-files.md).

## Step 2 — `zones`

Declare the firewall itself plus the two networks it sits between.

```
#ZONE   TYPE
fw      firewall
net     ipv4
loc     ipv4
```

## Step 3 — `interfaces`

Bind each zone to a NIC. `detect` lets ShorewallNF derive the interface's networks.

```
#ZONE   INTERFACE   OPTIONS
net     eth0        detect
loc     eth1        detect
```

## Step 4 — `policy`

Default inter-zone verdicts, applied after the per-connection `rules` fall through. The LAN is
allowed out; every other flow hits the fail-closed defaults.

```
#SOURCE   DEST   POLICY   LOG
loc       net    ACCEPT
net       all    DROP     info
all       all    REJECT   info
```

## Step 5 — `rules`

Two per-connection rules: admin SSH to the firewall, and the DNAT port-forward that publishes an
internal web server. `loc:192.0.2.10` is the rewrite target — the DNAT rule both redirects the
packet and admits the forwarded flow.

```
#ACTION   SOURCE   DEST             PROTO   DPORT
ACCEPT    net      fw               tcp     22
DNAT      net      loc:192.0.2.10   tcp     80
```

## Step 6 — `snat`

Masquerade the LAN subnet as it egresses the WAN interface (source NAT is IPv4-only; see
[ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)).

```
#ACTION       SOURCE          DEST (egress interface)
MASQUERADE    192.0.2.0/24    eth0
```

The directory now holds five files:

```
router/
├── interfaces
├── policy
├── rules
├── snat
└── zones
```

## Step 7 — `check`

Preprocess and validate without emitting a ruleset. This catches typos, unknown zones, and
malformed rows before you ever touch nftables.

```bash
shorewallnf check router
```

```
OK: router: 5 files, 16 preprocessed lines
```

## Step 8 — `compile`

Compile to the `inet` nftables ruleset and print it as `python3-nftables` JSON. Nothing is
loaded — this is the artifact `apply` would install.

```bash
shorewallnf compile router
```

The output is the full ruleset (a `filter` table with `input`/`forward`/`output` hooks and a
`nat` table with `prerouting`/`postrouting`). The two NAT rules from this config compile to:

```json
{
  "add": {
    "rule": {
      "family": "inet",
      "table": "nat",
      "chain": "prerouting",
      "expr": [
        { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "eth0" } },
        { "match": { "op": "==", "left": { "payload": { "protocol": "tcp", "field": "dport" } }, "right": 80 } },
        { "dnat": { "addr": "192.0.2.10", "family": "ip" } }
      ]
    }
  }
}
```

```json
{
  "add": {
    "rule": {
      "family": "inet",
      "table": "nat",
      "chain": "postrouting",
      "expr": [
        { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "eth0" } },
        { "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "saddr" } },
          "right": { "prefix": { "addr": "192.0.2.0", "len": 24 } } } },
        { "masquerade": null }
      ]
    }
  }
}
```

The inbound TCP 80 on `eth0` is rewritten to `192.0.2.10`, and traffic leaving `eth0` from
`192.0.2.0/24` is masqueraded — exactly the router behaviour we set out to build.

## Step 9 — `apply`

On a real nftables host, install the ruleset. `apply` compiles, dry-run checks it with
`nft --check`, atomically loads it, and persists it to disk so it survives a reboot.

```bash
sudo shorewallnf apply router
```

```
applied: router
```

## Where to go next

- The other lifecycle verbs (`start`, `reload`, `stop`, `clear`, `restore`) are summarised in
  [Getting started](getting-started.md#lifecycle-verbs).
- Each config file's full syntax is catalogued in the
  [configuration file reference](reference/config-files.md).
