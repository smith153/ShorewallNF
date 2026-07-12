# Operations

How to run ShorewallNF day to day: the lifecycle verbs, what the **stopped** safe state
guarantees, and how the firewall survives a reboot.

Every verb takes the form `shorewallnf <verb> [config-dir]`. The verbs that only read a config
(`check`, `compile`) need no privileges; the verbs that touch the live kernel ruleset
(`apply`, `start`, `reload`, `restart`, `try`, `stop`, `clear`, `restore`) need `CAP_NET_ADMIN` —
run them as root (e.g. with `sudo`).

## Lifecycle verbs

| Verb | Config dir | Privileged | What it does |
|------|:----------:|:----------:|--------------|
| `check` | required | no | Preprocess and validate the config; emit **no** ruleset. A fast "does this config parse and validate?" gate. |
| `compile` | required | no | Compile the config into an nftables ruleset and print the JSON to stdout. Loads nothing. |
| `apply` | required | yes | Compile → dry-run check (`nft --check`) → atomically load the ruleset live → **persist** it to disk. |
| `start` | required | yes | Bring the firewall up: compile → dry-run check → atomically load. Does **not** persist. |
| `reload` | required | yes | Compile → dry-run check → atomically replace the running ruleset. Does **not** persist. |
| `restart` | required | yes | Alias of `reload`: atomically replace the running ruleset. |
| `try` | required | yes | [Safe-apply](#safe-apply-with-try): snapshot the running ruleset, compile → dry-run check → atomically load `DIR`, and — given an optional `timeout` — auto-revert to the pre-`try` state after the window. Does **not** persist. |
| `stop` | required | yes | Drop to the [stopped safe state](#the-stopped-safe-state): still admits declared admin access, drops the rest. |
| `clear` | required | yes | Remove all ShorewallNF-owned tables, leaving traffic **unfiltered**. |
| `restore` | none | yes | Re-load the last [persisted ruleset](#persistence-and-boot-restore) from disk, fail-closed. |

A few operational notes cross-checked against the CLI:

- **Every load is atomic and fail-closed.** `apply`/`start`/`reload`/`restart`/`stop`/`restore`
  hand nftables one transaction; a ruleset nft rejects commits nothing and leaves the running
  ruleset unchanged (the command exits non-zero with nft's error text). A wrong firewall never
  half-lands.
- **`apply` is the only verb that persists.** `start`, `reload`, and `restart` load the same
  compiled ruleset but do **not** write it to disk — so a reboot after a bare `start` comes up
  with the last *applied* ruleset, not the last *started* one. Use `apply` when you want the
  change to survive a reboot. See [Persistence and boot-restore](#persistence-and-boot-restore).
- **`start`, `reload`, and `restart` are currently equivalent** — all three compile the config
  and atomically replace the running ruleset (they differ only in the confirmation line printed).
  Incremental / differential reload is deferred future work.
- **`clear` takes a config-dir argument but ignores its contents.** It deletes a fixed set of
  ShorewallNF-owned tables (`inet filter`, `inet nat`) regardless of what the config compiles to,
  so a stale table is removed even when the current config would not create it. Co-resident
  tables owned by other tools are never touched. After `clear`, traffic to the host is
  **unfiltered** — this is a maintenance escape hatch, not a safe state; use `stop` for that.
- **`restore` takes no config-dir.** It operates on the persisted on-disk ruleset, not a config.

### Safe-apply with `try`

`try DIR [timeout]` loads a candidate config the way `start` does — compile → `nft --check`
dry-run → atomic load — but wraps it in an **auto-revert** so a change that locks you out of a
remote host cannot become permanent. It never persists (like `start`/`reload`, it leaves
`/var/lib/shorewallnf/ruleset.json` untouched), and the auto-revert model is fixed in
[ADR-0067](adr/0067-safe-apply-auto-revert-model.md) — see also
[lifecycle.md → safe-apply](lifecycle.md#safe-apply-with-auto-revert-try).

- **It snapshots the *running* ruleset first**, not the last-saved one, and writes that snapshot
  to its own path — never the persisted `ruleset.json`. If nothing was running (a stopped or
  cleared firewall), the revert target is `clear`, not a stale on-disk ruleset.
- **`try DIR` with no timeout** just applies the candidate. A compile or apply failure terminates
  without changing the running (or the saved) ruleset and exits non-zero with one clear error —
  the atomic load never half-lands.
- **`try DIR timeout`** applies the candidate, then **auto-reverts** to the pre-`try` state once
  the window elapses. The revert is unconditional — this verb asks for no confirmation (the
  interactive `safe-reload`/`safe-start` siblings are separate). `timeout` uses the same syntax as
  elsewhere: a bare number of seconds, or an `s`/`m`/`h` suffix (`30`, `45s`, `5m`, `2h`).
- **The revert is fail-closed.** If restoring the snapshot itself fails, the firewall lands in the
  [stopped safe state](#the-stopped-safe-state) rather than wide open.

```bash
# Apply a config for 5 minutes; if it locks you out, it reverts itself and you reconnect.
sudo shorewallnf try /etc/shorewallnf 5m
```

### A typical flow

```bash
# 1. Validate the config without touching anything.
shorewallnf check   /etc/shorewallnf

# 2. Inspect the compiled nftables JSON (optional).
shorewallnf compile /etc/shorewallnf

# 3. Load it live and persist it for the next boot.
sudo shorewallnf apply /etc/shorewallnf

# 4. After editing the config, re-load it.
sudo shorewallnf reload /etc/shorewallnf   # note: reload does not persist; use apply for that

# 5. Drop to the stopped safe state for maintenance.
sudo shorewallnf stop /etc/shorewallnf
```

## Visibility verbs (read-only)

`show` inspects the firewall and never changes it — every object is read-only by construction,
through a `list`-only seam that has no mutating form (see
[ADR-0065](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0065-operational-visibility-output-format.md)).
`list` and `ls` are exact synonyms of `show`. Objects differ in their **source**: `rules`,
`connections`, and `log` read **live kernel state** and take no config directory, while `zones` and
`policies` render **compile-time declarations** not recoverable from live state and so take a
config directory. `log` accepts an **optional** config directory (only to read `LOGFORMAT`).

| Verb | Privileged | What it does |
|------|:----------:|--------------|
| `show rules [-t {filter\|nat\|mangle\|raw}] [chain…]` | reads the live ruleset | Print the live rules of the named chains (all chains of the `filter` table by default), rendered as an annotated, columnar report. |
| `show connections` | reads live conntrack | Print the connections the kernel is currently tracking (via the `conntrack` utility), rendered as a columnar report. |
| `show log [config_dir] [-n N]` | reads the systemd journal | Print a bounded tail of recent firewall log messages (default 20; `-n`/`--lines N` overrides), read from the kernel journal and filtered to lines bearing the `LOGFORMAT` prefix. |
| `show zones <config_dir>` | reads the config | Print the declared zones and their interface/host members from the config. |
| `show policies <config_dir>` | reads the config | Print the inter-zone default-policy matrix from the config. |

The `show rules` output is grouped by chain, with rules numbered within each chain and human
`TARGET` labels (`ACCEPT`/`DROP`/`DNAT`/…) — not raw `nft list` output:

```
Table: inet filter

Chain input (policy drop)
  NUM  TARGET  PROTO  SOURCE         DESTINATION  DETAIL
    1  ACCEPT  all    any            any          ct state {established,related}
    2  ACCEPT  tcp    192.0.2.0/24   any          dport {80,443}
```

The `DETAIL` column carries whatever doesn't fit a dedicated column: a `REJECT`'s reason
(`with icmpx admin-prohibited`, `with tcp reset`), and a `DNAT`/`SNAT` target with its address and
port rendered compactly — ranges as `192.0.2.1-192.0.2.10`, sets as `{a,b}`, plus any NAT `flags`
(`to 192.0.2.10:80 flags random`).

When the firewall is stopped or cleared, `show rules` prints an empty-but-valid report and exits 0
rather than erroring; a chain name that does not exist in a running table fails fast with one clear
error.

`show connections` renders each tracked flow's original direction — protocol, TCP state
(`-` when the protocol is stateless), source, destination, and `sport->dport` ports:

```
Connections

  PROTO  STATE        SOURCE         DESTINATION   PORTS
  tcp    ESTABLISHED  192.0.2.2      203.0.113.9   54321->443
  udp    -            192.0.2.5      198.51.100.4  1234->53
```

When the kernel is tracking nothing — including while the firewall is stopped or cleared —
`show connections` prints an empty-but-valid report and exits 0. If the `conntrack` utility is
not installed it fails fast with one actionable error (install `conntrack-tools`), not a stack
trace.

`show log` prints the most-recent firewall log messages, one per line, near their native form:

```
Firewall log

  Shorewall:net-fw:DROP:IN=eth0 OUT= SRC=203.0.113.7 DST=192.0.2.1 PROTO=TCP SPT=51000 DPT=23
  Shorewall:fw-net:REJECT:IN= OUT=eth0 SRC=192.0.2.1 DST=203.0.113.9 PROTO=TCP SPT=44444 DPT=25
```

The lines come from the systemd kernel journal (`journalctl -k`), where nft `log` statements land
(ShorewallNF packages only systemd and has no `LOGFILE` setting). Only lines bearing the `LOGFORMAT`
prefix are shown; the default bound is the 20 most-recent, overridable with `-n`/`--lines N`. Pass a
config directory to read a non-default `LOGFORMAT` from it (otherwise the default template applies).
When the journal holds no matching lines it prints an empty-but-valid report and exits 0; if the
journal reader is unavailable it fails fast with one actionable error, not a stack trace.

### `status`

`status` reports the **short firewall state** in one line — derived from the live ruleset (are the
ShorewallNF-owned tables present?), so it takes no config directory and is read-only:

```
$ shorewallnf status
Firewall: loaded
```

A stopped or cleared firewall (no owned tables) reports `Firewall: stopped or cleared` and exits 0
rather than erroring. Adding `-i <config_dir>` extends the report with per-declared-interface state,
combining the interfaces declared in the config with their live up/down link state (read via `ip`):

```
$ shorewallnf status -i /etc/shorewallnf
Firewall: loaded

Interfaces

  INTERFACE  STATE
  eth0       up
  eth1       down
```

### `dump`

`dump <config_dir>` emits **one consolidated read-only report** — the paste-into-a-bug-report view.
It is a pure aggregator: it invents no new collection or renderer, just concatenates the existing
`show`/`status` seams in a fixed order behind labelled section headers:

1. **Ruleset** — the live packet-filter rules (same source as `show rules`).
2. **Zones** — the declared zones and their members (same source as `show zones`).
3. **Policies** — the inter-zone default-policy matrix (same source as `show policies`).
4. **Connections** — the kernel-tracked connections (same source as `show connections`).
5. **Firewall log** — a bounded tail of recent firewall log messages (same source as `show log`,
   20 lines).

It takes a config directory because the zones/policies sections render compile-time declarations
and the log section reads `LOGFORMAT` from it. Like every visibility verb it is read-only and leaves
the loaded and saved ruleset byte-for-byte unchanged.

Each section **degrades independently**: if one source is unavailable (e.g. `conntrack` not
installed, the firewall stopped, the journal unreadable), that section shows an actionable
`(unavailable: …)` note in place while every other section still renders — one failing source never
aborts the whole report.

## The stopped safe state

`stop` does **not** open the firewall wide, and it does **not** slam it fully shut. Both are
dangerous: an `ACCEPT`-all "stopped" state exposes the host exactly when its managed rules are
down, while a `DROP`-all state locks the operator out of a remote box with no way back in.
Instead, `stop` installs a small, self-contained, fail-closed ruleset with a **no-lockout
guarantee**.

The stopped ruleset is:

1. **Default-drop** on `input` and `forward`, `accept` on `output` — the same fail-closed base
   as the running firewall.
2. A fixed **no-lockout baseline**, always present regardless of what you declare: accept
   `established`/`related` connections on `input` and `forward`, and accept loopback on `input`.
   This keeps an in-flight admin session (e.g. an open SSH connection) alive across the `stop`
   and admits loopback — without opening any new inbound port.
3. The **admin-access rules you declare** in the `stoppedrules` config file, translated by the
   same family-aware machinery as normal rules. This is where you allow, for example, SSH from a
   management host so a remote `stop` never orphans your access.

The stopped state is built **only** from `stoppedrules` — never from the running `rules`,
`policy`, or NAT — so it stays a minimal, auditable safe state that is independent of the
(possibly broken) config you just stopped. Even with **zero** admin rules declared, the baseline
alone still admits existing sessions and loopback, so `stop` can never silently lock you out.

## Persistence and boot-restore

An applied ruleset lives only in kernel memory, so a reboot would otherwise wipe it and bring
the host up with no firewall. ShorewallNF persists the effective ruleset on `apply` and can
re-load it after a reboot.

- **Where it lives.** The effective ruleset is saved to `/var/lib/shorewallnf/ruleset.json`
  (`/var/lib` is the FHS home for persistent application state). It holds the generated nftables
  JSON verbatim.
- **When it is written (save-on-apply).** A successful `apply` persists the exact ruleset it
  loaded, immediately after the live load succeeds — so a rejected load never overwrites a good
  saved ruleset. This is the **only** auto-save: `start`/`reload`/`restart` do not persist.
- **How it is written.** The file is created owner-only (`0o600`) — a ruleset can encode network
  topology, so it is never world-readable — and published atomically (temp file + `fsync` +
  rename). A reader sees either the old file or the new one, never a truncated one, so a crash
  mid-save can't leave a partial file that a boot restore would then load.
- **Restoring it.** `sudo shorewallnf restore` reads that file and re-applies it through the same
  atomic applier. The saved artifact is exactly the JSON that was applied, so it **round-trips**:
  restore is simply "re-apply the saved ruleset," with no separate restore format. It is
  fail-closed — a missing, corrupt, or nft-rejected file makes `restore` exit non-zero and leaves
  the prior live ruleset intact rather than flushing to an empty (wide-open) state.

### Boot-time restore

To protect the host across reboots, `shorewallnf restore` needs to run from an early-boot hook
that executes **before** network interfaces are brought up, and that treats a non-zero exit as
fatal (do not bring the network up if the restore fails) — this closes any window where the
host is reachable without its firewall. On systemd hosts, the packaged
`shorewallnf-restore.service` is exactly that hook — see [Running as a systemd
service](#running-as-a-systemd-service) below. On another init system, wire `shorewallnf
restore` into its equivalent early-boot path yourself, with the same before-the-network,
fail-fatal contract.

## Running as a systemd service

ShorewallNF ships two systemd units — install location(s), the `/etc/shorewallnf` default
config dir, and the non-hardcoded binary path are all fixed by
[ADR-0064](adr/0064-systemd-service-model-and-install-seam.md); see [Getting started →
Install](getting-started.md#install) to get them onto the host.

| Unit | Runs | Does |
|------|------|------|
| `shorewallnf-restore.service` | Before `network-pre.target`, at every boot | `shorewallnf restore` — re-applies the last [persisted ruleset](#persistence-and-boot-restore), fail-closed. |
| `shorewallnf.service` | At `multi-user.target`, `After=shorewallnf-restore.service` | `ExecStart=shorewallnf start /etc/shorewallnf` / `ExecStop=shorewallnf stop /etc/shorewallnf` — compiles and loads the **current** config, and drops to the [stopped safe state](#the-stopped-safe-state) on stop. |

The two are ordered so they never race: the restore unit fully completes — it is `Type=oneshot`
with `RemainAfterExit=yes` — before the main service starts, so a pre-network fail-closed
restore is always followed by, never overlapped with, the multi-user load of the current
config. See [ADR-0064 §4](adr/0064-systemd-service-model-and-install-seam.md) for the full
ordering rationale, and [lifecycle.md](lifecycle.md#boot-time-restore-systemd) for the restore
unit's own design detail.

Bring the firewall up now and on every future boot:

```bash
sudo systemctl enable --now shorewallnf-restore.service shorewallnf.service
```

`shorewallnf.service` alone (`systemctl enable --now shorewallnf`) compiles and loads
`/etc/shorewallnf` immediately, the same as a bare `shorewallnf start`; enabling
`shorewallnf-restore.service` too is what closes the pre-network window on every *subsequent*
reboot, since the main service itself only starts once `multi-user.target` is reached — well
after the network is already up.

Drop to the stopped safe state and stop the service:

```bash
sudo systemctl stop shorewallnf
```

This runs `ExecStop=shorewallnf stop /etc/shorewallnf` — the same [stopped safe
state](#the-stopped-safe-state) as running the verb directly, still admitting declared
`stoppedrules` access and dropping the rest.

**Enable-on-boot replaces `STARTUP_ENABLED`.** Upstream Shorewall's `shorewall.conf` has a
`STARTUP_ENABLED=Yes/No` setting gating whether an init script does anything on boot.
ShorewallNF has no such config key — `shorewallnf.conf` rejects it as an unknown setting (see
the [`shorewallnf.conf` reference](reference/shorewallnf-conf.md#unknown-keys-and-bad-values-fail-fast)).
The equivalent is systemd's own enablement: `systemctl enable` (or `enable --now`) makes the
unit start on every boot; leaving it disabled means the firewall only comes up when you run
`shorewallnf start`/`apply` (or `systemctl start`) by hand. This is documented operator
behaviour, not a config-file knob.

## See also

- [Getting started](getting-started.md) — install ShorewallNF, the config dir, and the systemd units.
- [Configuration files](reference/config-files.md) — the config directory the verbs read.
- [Save/restore lifecycle](lifecycle.md) — the persistence model and the boot-time restore unit in detail.
- [ADR-0021 — stopped safe-state ruleset](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0021-stopped-safe-state.md) — the no-lockout design.
- [ADR-0030 — reboot-persistence model](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0030-reboot-persistence-model.md) — state location, save-on-apply, restore contract.
- [ADR-0064 — systemd service model and install seam](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0064-systemd-service-model-and-install-seam.md) — config dir default, unit install locations, binary resolution, two-unit ordering.
