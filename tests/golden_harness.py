"""Golden-file snapshot harness (task #114, epic #77).

The hermetic, no-root TDD workhorse: render an IR :class:`~shorewallnf.ir.Ruleset` to
nftables JSON, diff it against a checked-in fixture under ``tests/golden/``, and — where
``python3-nftables`` is installed — assert the same output passes an ``nft -c`` dry-run
(:func:`shorewallnf.applier.check_ruleset`). The nft step is skipped cleanly where the
system dependency is absent, so the tier stays green without root (see epics #77/#78).

Regenerate a fixture on purpose with ``UPDATE_GOLDEN=1`` (or ``update=True``); a normal run
never rewrites it. See ``tests/golden/README.md`` for conventions.
"""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any

from shorewallnf.generator import generate
from shorewallnf.ir import Ruleset

GOLDEN_DIR = Path(__file__).parent / "golden"


def nft_available() -> bool:
    """True when ``python3-nftables`` is importable (the ``nft -c`` dry-run can run)."""
    try:
        import nftables  # type: ignore[import-not-found]  # noqa: F401  # optional system dep
    except ImportError:
        return False
    return True


def _update_requested() -> bool:
    return os.environ.get("UPDATE_GOLDEN") not in (None, "", "0")


def assert_golden(
    ruleset: Ruleset,
    name: str,
    *,
    golden_dir: Path = GOLDEN_DIR,
    update: bool | None = None,
    check_nft: bool = True,
) -> dict[str, Any]:
    """Render ``ruleset`` and assert it matches ``<golden_dir>/<name>.json``.

    On mismatch raise ``AssertionError`` with a unified diff. With ``update`` (defaulting to
    the ``UPDATE_GOLDEN`` env var) the fixture is rewritten instead of compared. Where
    ``python3-nftables`` is installed the rendered output is also dry-run validated (``nft -c``)
    unless ``check_nft`` is false. Returns the rendered ruleset.
    """
    actual = generate(ruleset)
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
