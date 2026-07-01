"""Applier — the imperative shell that validates/loads a ruleset with nftables.

All ``nft`` invocation lives here (ADR-0003 imperative shell). :func:`check_ruleset` dry-run
loads the generated JSON ruleset — the equivalent of ``nft -c`` — via the system
``python3-nftables``, raising :class:`~shorewallnf.errors.ConfigError` if nft rejects it.

``python3-nftables`` is a system dependency absent from CI tiers without it (the behavioral
netns tier, epics #77/#78); callers gate on its availability until that tier is enabled.
"""

from __future__ import annotations

from typing import Any

from .errors import ConfigError


def check_ruleset(ruleset: dict[str, Any]) -> None:
    """Dry-run load the nftables JSON ``ruleset`` (like ``nft -c``); raise on rejection."""
    import nftables  # type: ignore[import-not-found]  # optional system dep (python3-nftables)

    nft = nftables.Nftables()
    nft.set_dry_run(True)
    rc, _output, error = nft.json_cmd(ruleset)
    if rc != 0:
        raise ConfigError(f"generated ruleset rejected by nft: {error}")
