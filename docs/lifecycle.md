# Save / restore lifecycle and reboot persistence

A firewall that vanishes on reboot is not a firewall. ShorewallNF persists the effective
ruleset to disk when you apply it and restores it at boot **before the network comes up**, so
the machine boots into its intended firewall state rather than an unprotected one.

The persistence model — where state lives, when it is written, the round-trip guarantee — is
fixed in [ADR-0030](adr/0030-reboot-persistence-model.md). This document is the operator-facing
view: the lifecycle end to end and how to enable boot-time restore.

## The lifecycle

```
apply  ─►  (live load via nft)  ─►  save  ─►  /var/lib/shorewallnf/ruleset.json
                                                      │
reboot  ────────────────────────────────────────────►│
                                                      ▼
boot   ─►  shorewallnf-restore.service  ─►  restore  ─►  (live load, before the network)
```

1. **apply** — `shorewallnf apply <config-dir>` compiles the config, dry-run checks it
   (`nft --check`), atomically loads it live, and then **saves** the exact ruleset it loaded.
2. **persist** — the save writes that ruleset to the on-disk state path (below). This is the
   documented *save-on-apply* default: a successful `apply` always persists, and only `apply`
   auto-saves (no broader "save on every change" policy — see ADR-0030).
3. **restore-at-boot** — on the next boot the packaged systemd unit runs
   `shorewallnf restore`, which reads the persisted ruleset and re-applies it through the same
   atomic applier, before any interface is configured.

The saved artifact is the exact JSON handed to the applier, so it **round-trips**: what is
saved is exactly what re-applies. `restore` is therefore just "re-apply the saved ruleset" —
there is no separate restore format.

## Where state lives

| What | Path |
|---|---|
| Persisted effective ruleset | `/var/lib/shorewallnf/ruleset.json` |

`/var/lib` is the FHS home for persistent application state. The file is the generated
nftables JSON verbatim. It is written atomically (temp file + `fsync` + `rename`) and created
owner-only (`0o600`) — a ruleset can encode network topology, so it is never world-readable,
and a crash mid-save never leaves a truncated file that a boot restore would then load. The
path is `applier.DEFAULT_RULESET_PATH` in code.

## Boot-time restore (systemd)

The packaged unit is
[`packaging/systemd/shorewallnf-restore.service`](../packaging/systemd/shorewallnf-restore.service).
Install and enable it:

```bash
cp packaging/systemd/shorewallnf-restore.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable shorewallnf-restore.service
```

The unit's `ExecStart=` names the `shorewallnf` binary without a directory, so systemd resolves
it against its executable search path (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin`) — it
works whether the binary is installed at `/usr/bin` (distro package) or `/usr/local/bin`
(`pip install`), no edit required. The install seam (config dir, unit location, binary
resolution, and the two-unit ordering) is fixed in
[ADR-0064](adr/0064-systemd-service-model-and-install-seam.md).

### Ordering rationale: no unprotected boot window

The unit is ordered **before the network is configured** so the host is never briefly
reachable without its firewall:

```ini
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target
```

`network-pre.target` is the systemd synchronization point that network-management units
(`systemd-networkd`, `NetworkManager`, …) order themselves *after* — it exists precisely for
"set up the firewall before the network" units. `Wants=` pulls it into the boot transaction and
`Before=` slots the restore ahead of it; `DefaultDependencies=no` lifts the default late
ordering so nothing drags the unit back behind `basic.target`. The unit still orders itself
`After=local-fs.target` (with `RequiresMountsFor=/var/lib/shorewallnf`) so the state filesystem
is mounted before it reads the saved ruleset.

This restore unit is one half of a two-unit boot model: it re-applies the persisted ruleset
pre-network, and a second unit, `shorewallnf.service`, brings up the **current** config once
the system reaches `multi-user.target`, ordered `After=` this one. See [Operations → Running as
a systemd service](operations.md#running-as-a-systemd-service) for the main service, the
ordering contract, and the `systemctl enable --now` / `stop` operator flow.

### Fail-closed

Boot-time restore is fail-closed: a missing, corrupt, or nft-rejected saved ruleset makes
`shorewallnf restore` exit non-zero, which fails the unit **loudly**. The unit does not use an
`ExecStart=-` prefix that would swallow the error, and the `restore` verb is atomic and never
flushes the live ruleset to an empty (wide-open) state — so a failed restore leaves the prior
state rather than an unprotected host. A failed unit is visible in `systemctl --failed` and the
journal.

## Other init systems

Only systemd is packaged today — both `shorewallnf-restore.service` (this page) and the main
`shorewallnf.service` ([Operations → Running as a systemd
service](operations.md#running-as-a-systemd-service)). On other init systems, run `shorewallnf
restore` from an equivalent early boot hook that executes **before** network interfaces are
brought up and treats a non-zero exit as fatal (do not bring the network up if restore fails).
Packaging for non-systemd init systems is documented future work (epic #202).

## See also

- [ADR-0030](adr/0030-reboot-persistence-model.md) — the persistence model (state location,
  save-on-apply default, round-trip guarantee, restore-at-boot contract).
- [ADR-0064](adr/0064-systemd-service-model-and-install-seam.md) — the two-unit boot model,
  install seam, and ordering contract.
- [Operations → Running as a systemd service](operations.md#running-as-a-systemd-service) —
  the operator flow: `systemctl enable --now` / `stop`.
- [ARCHITECTURE.md](ARCHITECTURE.md) — the compiler pipeline and the Applier stage.
