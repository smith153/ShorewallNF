# Getting started

!!! warning "Skeleton page"
    A stub to be expanded as the install/packaging story lands. Commands below reflect the
    current CLI; paths and packaging will firm up with the systemd/packaging work.

## Requirements

- Linux with a modern **nftables** kernel and the `nft` userspace tool.
- **Python ≥ 3.11** and the system **`python3-nftables`** module.

## Install (from source)

```bash
git clone https://github.com/smith153/ShorewallNF.git
cd ShorewallNF
python -m pip install -e .
```

This installs the `shorewallnf` command.

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
directory.
