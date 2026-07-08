# Operations

How to run ShorewallNF day to day: the lifecycle verbs, what the **stopped** safe state
guarantees, and how the firewall survives a reboot.

Every verb takes the form `shorewallnf <verb> [config-dir]`. The verbs that only read a config
(`check`, `compile`) need no privileges; the verbs that touch the live kernel ruleset
(`apply`, `start`, `reload`, `restart`, `stop`, `clear`, `restore`) need `CAP_NET_ADMIN` — run
them as root (e.g. with `sudo`).

## Lifecycle verbs

| Verb | Config dir | Privileged | What it does |
|------|:----------:|:----------:|--------------|
| `check` | required | no | Preprocess and validate the config; emit **no** ruleset. A fast "does this config parse and validate?" gate. |
| `compile` | required | no | Compile the config into an nftables ruleset and print the JSON to stdout. Loads nothing. |
| `apply` | required | yes | Compile → dry-run check (`nft --check`) → atomically load the ruleset live → **persist** it to disk. |
| `start` | required | yes | Bring the firewall up: compile → dry-run check → atomically load. Does **not** persist. |
| `reload` | required | yes | Compile → dry-run check → atomically replace the running ruleset. Does **not** persist. |
| `restart` | required | yes | Alias of `reload`: atomically replace the running ruleset. |
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

To protect the host across reboots, run `shorewallnf restore` from an early-boot hook that
executes **before** network interfaces are brought up, and that treats a non-zero exit as fatal
(do not bring the network up if the restore fails) — this closes any window where the host is
reachable without its firewall.

!!! note "systemd integration is forthcoming"
    A packaged systemd unit and an install/packaging seam that wires boot-time restore in for you
    are **forthcoming** — tracked by the [systemd service + packaging epic (#308)](https://github.com/smith153/ShorewallNF/issues/308).
    The intended unit orders itself before `network-pre.target` (so restore runs ahead of any
    network-management service) and fails loudly on a bad ruleset. Until that install seam lands,
    wire `shorewallnf restore` into your init system's early-boot path yourself, as above.

## See also

- [Getting started](getting-started.md) — install ShorewallNF and compile your first config.
- [Configuration files](reference/config-files.md) — the config directory the verbs read.
- [ADR-0021 — stopped safe-state ruleset](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0021-stopped-safe-state.md) — the no-lockout design.
- [ADR-0030 — reboot-persistence model](https://github.com/smith153/ShorewallNF/blob/master/docs/adr/0030-reboot-persistence-model.md) — state location, save-on-apply, restore contract.
