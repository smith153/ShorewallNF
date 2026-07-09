# stoppedrules

The `stoppedrules` file declares the traffic that stays permitted while the firewall is
**stopped**. `shorewallnf stop` does not tear the firewall down to an open (accept-all) or a
fully closed (drop-all) state — both are dangerous. It installs a small, self-contained
**stopped safe-state** ruleset that fails closed by default but keeps the admin-access rules you
declare here in force, so a remote `stop` can never lock the operator out
([ADR-0021](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0021-stopped-safe-state.md)).

A typical entry permits management access — for example SSH from a management host.

## Row format

`stoppedrules` shares the [`rules`-file grammar](config-files.md), but it is **filter-only**:

```
ACTION  SOURCE  DEST  [PROTO]  [DEST PORT]  [SOURCE PORT]
```

Columns are whitespace-separated; `-` marks an unspecified optional column. A `DNAT` row has no
meaning in the stopped safe state and is rejected with a `file:line` error — `stoppedrules`
carries admin-access filter rules only. An empty or absent file is fine (it yields no extra
stopped rules; the no-lockout fallback still applies).

| Column | Required | Accepted values |
|--------|----------|-----------------|
| `ACTION` | yes | A filter verdict or action name (e.g. `ACCEPT`, `DROP`). `DNAT` is rejected. |
| `SOURCE` | yes | A `zone` or `zone:host`, where `host` is an IPv4/IPv6 address or CIDR literal. |
| `DEST` | yes | A `zone` or `zone:host`, same forms as `SOURCE`. |
| `PROTO` | no | A protocol name (e.g. `tcp`, `udp`, `icmp`); case-insensitive. |
| `DEST PORT` | no | The destination port (a number or service name). |
| `SOURCE PORT` | no | The source port. |

### Family

Family is inferred per row exactly as for `rules`
([ADR-0002](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0002-unified-inet-dual-stack.md)):
a host literal or an `icmp`/`ipv6-icmp` proto pins the family; a bare zone-to-zone row with no
literal stays dual-stack. Mixing families within one row fails fast.

## Examples

Permit SSH from a management host to the firewall itself while stopped (`fw` here is the
firewall-type zone named in the `zones` file — reference zones by their literal name):

```
#ACTION  SOURCE               DEST  PROTO  DEST PORT
ACCEPT   net:192.0.2.10       fw    tcp    22
```

Permit SSH from a management subnet, IPv4 and IPv6:

```
#ACTION  SOURCE                 DEST  PROTO  DEST PORT
ACCEPT   net:198.51.100.0/24    fw    tcp    22
ACCEPT   net:2001:db8:10::/64   fw    tcp    22
```

A `DNAT` row here is an error — port-forwarding has no place in the stopped state:

```
#ACTION  SOURCE  DEST
DNAT     net     loc:192.0.2.5     # rejected: DNAT not allowed in stoppedrules
```
