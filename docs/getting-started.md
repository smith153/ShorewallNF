# Getting started

## Requirements

- Linux with a modern **nftables** kernel and the `nft` userspace tool.
- **Python ≥ 3.11** and the system **`python3-nftables`** module.

## Install

### The `shorewallnf` binary

No packaged release exists yet — install from source with `pip`:

```bash
git clone https://github.com/smith153/ShorewallNF.git
cd ShorewallNF
python -m pip install -e .
```

This installs the `shorewallnf` command onto your `PATH` (e.g. `/usr/local/bin/shorewallnf` for
a user-level `pip install`, `/usr/bin/shorewallnf` from a distro package). The shipped systemd
units below name the binary without a directory (`ExecStart=shorewallnf ...`), so systemd
resolves it against its own executable search path regardless of exactly where `pip` put it —
see [ADR-0064 §3](adr/0064-systemd-service-model-and-install-seam.md).

### The config directory

Configuration is a directory of Shorewall-style tabular files (`zones`, `policy`, `rules`, …;
see the [configuration file reference](reference/config-files.md)). The documented default is
**`/etc/shorewallnf`** — the lifecycle verbs' `[config-dir]` argument and the packaged systemd
units below both assume it unless you pass a different directory explicitly
([ADR-0064 §1](adr/0064-systemd-service-model-and-install-seam.md)):

```bash
sudo mkdir -p /etc/shorewallnf
# ... populate zones, policy, rules, etc.
```

### The systemd unit files

ShorewallNF ships two units under
[`packaging/systemd/`](https://github.com/smith153/ShorewallNF/tree/master/packaging/systemd):
`shorewallnf-restore.service` (boot-time restore) and `shorewallnf.service` (the main
start/stop lifecycle). See [Operations → Running as a systemd
service](operations.md#running-as-a-systemd-service) for how the two work together.

Install them and reload systemd's unit cache:

```bash
sudo cp packaging/systemd/shorewallnf-restore.service packaging/systemd/shorewallnf.service \
    /etc/systemd/system/
sudo systemctl daemon-reload
```

`/etc/systemd/system` is the local-admin install location. A distro package instead places
units under the vendor directory, `/usr/lib/systemd/system` — systemd reads both, with `/etc`
overriding `/usr/lib` ([ADR-0064 §2](adr/0064-systemd-service-model-and-install-seam.md)).

## Compile and apply a config

Point `shorewallnf` at a Shorewall-style configuration directory:

```bash
# Preprocess and validate only — emit no ruleset:
shorewallnf check   /etc/shorewallnf

# Compile to nftables JSON (prints the ruleset):
shorewallnf compile /etc/shorewallnf

# Compile, dry-run check with `nft --check`, atomically load, and persist:
sudo shorewallnf apply /etc/shorewallnf
```

## Lifecycle verbs

| Verb | What it does |
|------|--------------|
| `check` | Preprocess + validate the config; emit no ruleset. |
| `compile` | Compile the config into an nftables ruleset (prints it). |
| `apply` | Compile, `nft --check`, atomically load, then persist to disk. |
| `start` | Bring the firewall up (compile → check → atomic load). |
| `reload` / `restart` | Atomically replace the running ruleset. |
| `stop` | Drop to the stopped safe state — still admits declared admin access, drops the rest. |
| `clear` | Remove all ShorewallNF tables, leaving traffic unfiltered. |
| `restore` | Reload the last persisted ruleset from disk, fail-closed. |

See the [configuration file reference](reference/config-files.md) for what goes in the config
directory, and [Operations](operations.md) for running these verbs day to day — including
[running as a systemd service](operations.md#running-as-a-systemd-service) instead of driving
the CLI by hand.
