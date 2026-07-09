# `shorewallnf.conf`

`shorewallnf.conf` is an **optional** file in the config directory that holds whole-ruleset
settings — logging level/prefix and a handful of kernel sysctl toggles — that don't belong as
a row in any tabular file. See
[ADR-0061](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0061-shorewallnf-conf-settings-file.md)
for the design rationale.

## File format

- One **`KEY=value`** (or **`KEY="value"`** / **`KEY='value'`**) assignment per line. Quotes
  are stripped; they only matter for preserving surrounding whitespace or an empty value.
- `KEY` is uppercase `[A-Z0-9_]+`.
- `#` begins a comment to end of line; blank lines are ignored.
- The file is **never shell-sourced**: no `export`, no line continuations, no `$VAR` / `` `cmd` ``
  / `$(cmd)` expansion, no word-splitting. A `$` in a value is a literal `$`. (This is unrelated
  to the [`params`](params.md) substitution used in the tabular files — `shorewallnf.conf` gets
  none of that.)
- The file is **not** preprocessed and not passed through the row/column tokenizer that parses
  `zones`, `policy`, `rules`, etc. — it has its own small parser.

## Unknown keys and bad values fail fast

A firewall compiler that silently ignores a setting is worse than one that refuses to run:

- An **unknown key** — a typo, or a legacy Shorewall `shorewall.conf` knob ShorewallNF doesn't
  implement (e.g. `STARTUP_ENABLED`, `IPTABLES`) — is a hard error naming the file, line, and
  key: `shorewallnf.conf:12: unknown setting 'STARTUP_ENABLED'`.
- A **malformed value** for a known key (not one of its accepted values, too long, etc.) is a
  hard error with the same file/line/key context — with one exception: `LOG_LEVEL` only rejects
  an empty value and otherwise accepts anything; see
  [`LOG_LEVEL` / `LOGFORMAT`](#log_level-logformat) below.
- A **malformed line** (no `=`, empty key, bad key charset) is a hard error.

There is no warn-and-ignore and no partial acceptance — the compile stops at the first
offending line.

## Absent file / absent key

`shorewallnf.conf` is entirely optional. If it's missing from the config directory, or a
supported key is simply not set, that key takes its **default** below — and every default is
chosen to reproduce ShorewallNF's behaviour as if the file didn't exist at all. Adopting the
file is opt-in and doesn't change output unless you actually set a key to a non-default value.

## Supported keys

Only the keys listed here are accepted — every other ADR-0061 key is still an unknown key and
fails fast until the epic that implements it lands (see [Keys not yet supported](#keys-not-yet-supported)).

| Key | Values | Default | Effect |
|-----|--------|---------|--------|
| `LOG_LEVEL` | Any non-empty string (unvalidated) | `info` | Fallback log level for a logging rule/policy that doesn't specify its own `LOG LEVEL` column. |
| `LOGFORMAT` | A template string with up to two `%s` slots | `Shorewall:%s:%s:` | The log-prefix template for emitted `log` statements; the two `%s` slots fill with the chain name and the disposition (action). The *rendered* prefix must fit the kernel's 127-character log-prefix limit. |
| `IP_FORWARDING` | `On` / `Off` / `Keep` | `Keep` | Writes `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding` (`On`→`1`, `Off`→`0`). `Keep` leaves the kernel value untouched. |
| `LOG_MARTIANS` | `Yes` / `No` / `Keep` | `Keep` | Writes `net.ipv4.conf.{all,default}.log_martians` (`Yes`→`1`, `No`→`0`). `Keep` leaves it untouched. IPv4-only; there is no IPv6 kernel equivalent. |
| `ROUTE_FILTER` | `Yes` / `No` / `Keep` | `Keep` | Writes `net.ipv4.conf.{all,default}.rp_filter` (`Yes`→`1`, `No`→`0`). `Keep` leaves it untouched. IPv4-only. |

Values for the tri-state (`On`/`Off`/`Keep`, `Yes`/`No`/`Keep`) keys are matched
case-insensitively.

### `LOG_LEVEL` / `LOGFORMAT`

These feed the nftables `log` statement the generator emits for a logging policy or rule. A
per-policy or per-rule `LOG LEVEL` column, when present, always wins — `LOG_LEVEL` is only the
level used when logging is requested with no explicit level of its own. `LOGFORMAT` supplies
the prefix template for every emitted log statement; see the
[`policy`](policy.md#log-level) reference for how per-row logging works.

`LOG_LEVEL` does **not** get the same fail-fast validation as the other four keys: the parser
rejects only an empty value and otherwise accepts any string verbatim, unlike the tabular
`policy`/`rules` `LOG LEVEL` column, which is checked against a fixed set of nft log-level
keywords (`emerg`/`alert`/`crit`/`err`/`warn`/`notice`/`info`/`debug`/`audit`) and rejects
anything else at parse time. A `shorewallnf.conf` `LOG_LEVEL` value that isn't one of those
keywords compiles without error and is passed straight into the generated `log` statement — it
would only surface as a problem, if ever, when nft loads the ruleset. Closing this gap so
`LOG_LEVEL` gets the same validation as the column is tracked separately (#367); until then,
stick to the keywords above even though the parser won't enforce it.

### `IP_FORWARDING` / `LOG_MARTIANS` / `ROUTE_FILTER`

These three are the applier's first kernel mutation outside nftables itself: after the
compiled ruleset is atomically loaded, the applier writes the requested sysctls, snapshotting
the prior value of each and rolling every write back (fail-closed) if any one of them fails.
`Keep` (the default for all three) means "leave whatever the kernel already has" — the sysctl
is never even read. See
[ADR-0062](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0062-applier-kernel-sysctl-mutation.md)
for the rollback design.

## Example

```
# shorewallnf.conf
LOG_LEVEL=notice
LOGFORMAT="FW:%s:%s:"
IP_FORWARDING=On
LOG_MARTIANS=Yes
ROUTE_FILTER=Yes
```

## Keys not yet supported

`shorewallnf.conf` mirrors a subset of upstream Shorewall's `shorewall.conf`, but only keys
with a real target in ShorewallNF today are accepted. The following ADR-0061 keys are
**recognized by name in the design** but have no consumer yet, so a `shorewallnf.conf` that
sets them fails fast the same as any unknown key — each is unlocked by the epic that builds
the behaviour it configures:

| Key(s) | Arrives with |
|--------|--------------|
| `RPFILTER_DISPOSITION` / `RPFILTER_LOG_LEVEL` | #310 (interface protective checks) |
| `TCP_FLAGS_DISPOSITION` / `TCP_FLAGS_LOG_LEVEL` | #310 |
| `SFILTER_DISPOSITION` / `SFILTER_LOG_LEVEL` | #310 |
| `BLACKLIST_DISPOSITION` / `BLACKLIST_LOG_LEVEL` | #310 |
| `CLAMPMSS` | #311 (generator global modes) |
| `DISABLE_IPV6` | #311 |

`REJECT_ACTION`, default-policy action overrides, `MULTICAST`, `OPTIMIZE`,
`DYNAMIC_BLACKLIST`, and `shorewallnf.conf` variable expansion are not modeled at all
(deferred, YAGNI) — see ADR-0061 for the full scope table.

## See also

- [ADR-0061 — `shorewallnf.conf` settings file, frozen `Settings` model, option scope](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0061-shorewallnf-conf-settings-file.md)
- [ADR-0062 — applier kernel sysctl mutation](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0062-applier-kernel-sysctl-mutation.md)
- [`policy`](policy.md) — per-policy `LOG LEVEL` column.
