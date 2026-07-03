"""Golden-file snapshot harness (task #114, epic #77).

The hermetic TDD workhorse: render an IR :class:`~shorewallnf.ir.Ruleset` to nftables JSON,
diff it against a checked-in fixture under ``tests/golden/``, and — where the ``nft`` binary
can run — assert the same output passes an ``nft --check`` dry-run
(:func:`shorewallnf.applier.check_ruleset`).

The generator emits the JSON with the stdlib ``json`` module, so the diff always runs with no
nftables tooling. Validation shells out to the ``nft`` binary; ``nft --check`` reads the kernel
ruleset cache and so needs CAP_NET_ADMIN (root), which the fast CI tier's unprivileged user
lacks. :func:`nft_available` probes whether nft can actually validate here, and
:func:`require_nft` turns a missing/broken nft into a HARD failure under CI (``GITHUB_ACTIONS``)
so the dry-run can never silently skip there, while still skipping locally for dev convenience
(task #165).

Regenerate a fixture on purpose with ``UPDATE_GOLDEN=1`` (or ``update=True``); a normal run
never rewrites it. See ``tests/golden/README.md`` for conventions.
"""

from __future__ import annotations

import difflib
import functools
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from shorewallnf.applier import NFT
from shorewallnf.generator import generate
from shorewallnf.ir import Ruleset

GOLDEN_DIR = Path(__file__).parent / "golden"

# A minimal, self-contained ruleset whose ``add table`` forces nft to initialise its kernel
# ruleset cache — the step that needs CAP_NET_ADMIN. Validating it is a faithful probe of
# "can ``nft --check`` actually run here", distinguishing root from an unprivileged shell.
_PROBE_RULESET: dict[str, Any] = {
    "nftables": [{"add": {"table": {"family": "inet", "name": "snf_nft_probe"}}}]
}


@functools.cache
def nft_available() -> bool:
    """True when ``nft --check`` can actually validate a ruleset here — the binary is present
    *and* usable (it needs CAP_NET_ADMIN). Cached; the probe is a side-effect-free dry-run."""
    if shutil.which(NFT) is None:
        return False
    result = subprocess.run(
        [NFT, "--check", "--json", "--file", "-"],
        input=json.dumps(_PROBE_RULESET),
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def in_ci() -> bool:
    """True when running under GitHub Actions (``GITHUB_ACTIONS`` set)."""
    return bool(os.environ.get("GITHUB_ACTIONS"))


def require_nft() -> None:
    """Gate an nft-dependent test on the ``nft --check`` dry-run being able to run.

    In CI a missing/broken nft is a HARD failure — the golden dry-run must never silently skip
    there (that silent skip was the whole defect, #165). Locally it skips for dev convenience,
    since ``nft --check`` needs root that a developer's test run usually lacks.
    """
    if nft_available():
        return
    if in_ci():
        raise AssertionError(
            "nft --check must run in CI but the `nft` binary is unavailable or lacks "
            "CAP_NET_ADMIN — install `nftables` and run the step privileged; refusing to skip"
        )
    pytest.skip("nft --check cannot run here (no binary / no CAP_NET_ADMIN); skipped for local dev")


def _update_requested() -> bool:
    return os.environ.get("UPDATE_GOLDEN") not in (None, "", "0")


def assert_golden(
    ruleset: Ruleset,
    name: str,
    *,
    golden_dir: Path = GOLDEN_DIR,
    update: bool | None = None,
    check_nft: bool = True,
    generator: Callable[[Ruleset], dict[str, Any]] = generate,
) -> dict[str, Any]:
    """Render ``ruleset`` and assert it matches ``<golden_dir>/<name>.json``.

    On mismatch raise ``AssertionError`` with a unified diff. With ``update`` (defaulting to
    the ``UPDATE_GOLDEN`` env var) the fixture is rewritten instead of compared. Where ``nft``
    can run the rendered output is also dry-run validated (``nft --check``) unless ``check_nft``
    is false; where it cannot the diff still runs (the non-vacuous CI guarantee comes from the
    ``require_nft``-gated tests, task #165). ``generator`` selects the render entry point (the
    running ruleset by default; ``generate_stopped`` for the stopped safe state). Returns the
    rendered ruleset.
    """
    actual = generator(ruleset)
    path = golden_dir / f"{name}.json"
    if update is None:
        update = _update_requested()

    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_dumps(actual))
    else:
        if not path.exists():
            raise AssertionError(
                f"golden fixture {path} is missing — create it with UPDATE_GOLDEN=1"
            )
        expected = json.loads(path.read_text())
        if actual != expected:
            raise AssertionError(
                f"generated ruleset does not match golden {path.name}:\n{_diff(expected, actual)}"
            )

    if check_nft and nft_available():
        from shorewallnf.applier import check_ruleset

        check_ruleset(actual)  # raises ConfigError if nft rejects the ruleset

    return actual


def _dumps(ruleset: dict[str, Any]) -> str:
    return json.dumps(ruleset, indent=2) + "\n"


def _diff(expected: dict[str, Any], actual: dict[str, Any]) -> str:
    return "\n".join(
        difflib.unified_diff(
            _dumps(expected).splitlines(),
            _dumps(actual).splitlines(),
            fromfile="golden",
            tofile="generated",
            lineterm="",
        )
    )
