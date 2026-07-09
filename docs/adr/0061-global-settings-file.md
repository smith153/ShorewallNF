# ADR-0061: global settings file (`shorewallnf.conf`)

- **Status:** Proposed
- **Date:** 2026-07-08

> **Numbering:** in the 0060s decade for global/runtime configuration (0060 records the QoS
> out-of-scope decision). If the Epic Decomposer reserves a different `NNNN` in the task that
> introduces this file, rename to match.

## Context

Every knob ShorewallNF exposes today is per-object and lives in a tabular file (`zones`,
`interfaces`, `policy`, …). There is no place to set behaviour that applies to the whole
ruleset — the default log level, what verdict a failed reverse-path check takes, whether IP
forwarding is enabled. Shorewall put these in `shorewall.conf`. `reader.py` deliberately
*ignores* any such file today (`KNOWN_CONFIG_FILES` whitelist), so the concept does not exist
yet.

We want the global-settings concept, but Shorewall's file is the wrong thing to copy wholesale:

- **Most of it is dead weight in an nftables-native rewrite.** `PERL`, `SHOREWALL_SHELL`,
  `IPTABLES`/`IPSET`/`TC` binary paths, `MODULESDIR`, `RESTOREFILE`, `MUTEX_TIMEOUT`,
  `LOCKFILE`, `PERL_HASH_SEED`, and the `TC_BITS`/`PROVIDER_BITS` packet-mark layout are all
  iptables/perl-runtime plumbing with no analog here.
- **Shorewall *shell-sources* `shorewall.conf`.** The file is executed by `/bin/sh`, so a
  config file is arbitrary code. That is a non-starter for a compiler whose whole point is to
  treat config as data (ADR-0003, functional core).
- **Silent-ignore is a footgun.** A firewall where a setting the operator wrote has no effect,
  with no error, is exactly the "subtly-wrong ruleset" failure ADR-0004 exists to prevent.

Forces: keep the runtime dependency surface minimal (stdlib only); keep the settings on the
pure side of the core so the Generator can consume them deterministically; fail fast on
anything we don't understand.

## Decision

We add an **optional** global settings file, **`shorewallnf.conf`**, read from the config
directory.

### 1. Name and compatibility

The file is named **`shorewallnf.conf`**, not `shorewall.conf`. The new name is deliberate: it
signals ShorewallNF is *not* a drop-in `shorewall.conf` consumer. A real `shorewall.conf` left
in the directory is still ignored as an unknown file, exactly as today.

### 2. Format — data, not code

Lines are `KEY=value` or `KEY="value"`. `#` begins a comment; blank lines are ignored. Values
are **literal strings** — the file is parsed, never shell-sourced, and there is **no variable
expansion** in v1 (`$LOG_LEVEL` interpolation and `params` reference are YAGNI until a real
need appears). Each key is parsed into a typed field (enum / bool / int / string) of a frozen
`Settings` dataclass in the IR.

### 3. Optional, with documented defaults

The file is optional. An absent file, or an absent key, yields the documented default for that
setting, so a config that never mentions settings behaves exactly as it does today. The default
`Settings` object is the single source of truth for those defaults.

### 4. Unknown keys are a hard error (ADR-0004)

Any key not in the supported set below — including legacy `shorewall.conf` knobs we
deliberately dropped — is a fail-fast `ConfigError` naming the file, line, and key. There is no
warn-and-ignore path: a setting either takes effect or stops the compile. A malformed value
(bad enum member, non-integer where an int is required) fails the same way.

### 5. Where it sits in the pipeline

`shorewallnf.conf` joins the reader whitelist and is parsed early into the `Settings` object,
which is threaded through the IR to the Generator and Applier. Settings split by where they
take effect:

- **Generation-time (pure core → Generator):** logging, dispositions, `CLAMPMSS`,
  `DISABLE_IPV6`. These change the emitted nftables JSON and stay entirely in the functional
  core.
- **Apply-time (imperative shell → Applier):** the sysctl-adjacent options (`IP_FORWARDING`,
  `LOG_MARTIANS`, `ROUTE_FILTER`). nftables does not own these; the Applier sets the
  corresponding kernel sysctls when it loads the ruleset, and reverts nothing on `clear` beyond
  what it set (details are the epic's to fix).

### 6. Supported option set (the "recommended cut")

The first cut is scoped to settings an operator hits immediately. Legacy/irrelevant knobs are
out of scope permanently; other still-meaningful options (`REJECT_ACTION`, default policy
actions, `MULTICAST`, `OPTIMIZE`, `DYNAMIC_BLACKLIST`) are deferred to later extensions of this
file, added when a task needs them.

**Logging**

| Key | Values | Default | nftables-native meaning |
|-----|--------|---------|-------------------------|
| `LOG_LEVEL` | syslog level (`emerg`…`debug`) | `info` | Default `log level` for rules that log. |
| `LOGFORMAT` | string with up to two `%s` | `Shorewall:%s:%s:` | Template for the `log prefix`; `%s` slots fill with chain / disposition. Default mirrors upstream Shorewall for migration compatibility. Length is validated against the kernel prefix limit. |
| `BLACKLIST_LOG_LEVEL` | syslog level or empty | empty (off) | Log level for the blacklist check; empty means don't log. |
| `TCP_FLAGS_LOG_LEVEL` | syslog level or empty | empty (off) | Log level for the invalid-TCP-flags check. |
| `RPFILTER_LOG_LEVEL` | syslog level or empty | empty (off) | Log level for the reverse-path check. |
| `SFILTER_LOG_LEVEL` | syslog level or empty | empty (off) | Log level for the source-filter (anti-spoof) check. |

**Dispositions** — the verdict a built-in protective check takes.

| Key | Values | Default | Meaning |
|-----|--------|---------|---------|
| `BLACKLIST_DISPOSITION` | `ACCEPT` \| `DROP` \| `REJECT` \| `CONTINUE` | `DROP` | Verdict for blacklisted packets. |
| `TCP_FLAGS_DISPOSITION` | same | `DROP` | Verdict for invalid TCP-flag combinations. |
| `RPFILTER_DISPOSITION` | same | `DROP` | Verdict when the reverse-path check fails. |
| `SFILTER_DISPOSITION` | same | `DROP` | Verdict when the source-filter check fails. |

**Sysctl-adjacent (apply-time)**

| Key | Values | Default | Meaning |
|-----|--------|---------|---------|
| `IP_FORWARDING` | `On` \| `Off` \| `Keep` | `Keep` | `On`/`Off` set `net.ipv4.ip_forward` + `net.ipv6.conf.all.forwarding`; `Keep` leaves the kernel value untouched. |
| `LOG_MARTIANS` | `Yes` \| `No` \| `Keep` | `Keep` | Sets `net.ipv4.conf.*.log_martians`. |
| `ROUTE_FILTER` | `Yes` \| `No` \| `Keep` | `Keep` | Sets `net.ipv4.conf.*.rp_filter` (kernel reverse-path filter). Distinct from an nft-level rpfilter rule. |

**Dual-stack / MSS (generation-time)**

| Key | Values | Default | Meaning |
|-----|--------|---------|---------|
| `DISABLE_IPV6` | `Yes` \| `No` | `No` | When `Yes`, the Generator emits no IPv6 rules and installs a base IPv6-drop so the `inet` ruleset is IPv4-only. |
| `CLAMPMSS` | `Yes` \| `No` \| `<pmtu>` | `No` | Clamp forwarded-SYN TCP MSS: `Yes` clamps to path MTU, an integer clamps to that value. |

Defaults are chosen to be safe and change nothing versus today's behaviour: `Keep` for every
sysctl (ShorewallNF does not silently reconfigure the kernel unless asked), dispositions
matching Shorewall's protective defaults, and logging off for the individual checks until a
level is set.

## Consequences

- **Easier:** whole-ruleset behaviour finally has a home; the Generator reads deterministic,
  typed settings instead of hard-coded constants (e.g. today's fixed log prefix and level).
  The `Settings` default object documents every knob and its default in one place.
- **New responsibility in the shell:** the Applier gains sysctl-setting for the three
  apply-time options — the first time it mutates kernel state outside nftables. Its
  fail-closed/rollback contract (ADR-0010/0021) must cover that.
- **Validation surface grows:** each option is a new way a config can be wrong, which feeds
  directly into the validator-hardening work. Fail-fast on unknown keys and bad values is the
  first line.
- **Not drop-in compatible, by choice:** a real `shorewall.conf` won't load unedited. We accept
  that in exchange for an honest, code-free, fail-fast settings model.
- **Follow-up:** this ADR fixes the file, format, and the recommended-cut option set. The epic
  implements the parser + `Settings` IR, wires it through the Generator and Applier, and
  documents each option. Deferred options extend the same file later.

## Alternatives considered

- **Reuse the `shorewall.conf` name.** Rejected: it implies drop-in compatibility we do not
  offer, and a legacy file full of unsupported keys would hard-error on first load — more
  surprising than an explicitly new file.
- **Shell-source the file (Shorewall's model).** Rejected outright: executing config as code
  breaks the functional-core boundary (ADR-0003) and is a security hole.
- **Warn-and-ignore unknown keys.** Rejected: a silently dropped setting the operator believes
  is in effect is the exact class of subtly-wrong-firewall bug ADR-0004 forbids.
- **Support the full still-relevant option set now.** Rejected as premature (YAGNI): each option
  is real semantics to define, generate, and validate. The recommended cut lands the machinery;
  the file extends option-by-option as tasks need them.
- **Variable expansion / `params` reference in values.** Deferred: no current need, and it
  reintroduces a mini-language into what is otherwise inert data.
