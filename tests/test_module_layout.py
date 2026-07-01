"""Guards for the compiler's module-layout doc (docs/module-layout.md).

A docs-only task, guarded like code: keep the stage->module map complete and
truthful, so it can't silently drift from the actual tree.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "module-layout.md"
PKG = ROOT / "src" / "shorewallnf"

# The pipeline stages from docs/ARCHITECTURE.md that the layout must place.
STAGES = ("Reader", "Preprocessor", "Parser", "IR", "Validator", "Generator", "Applier")

_MODULE = re.compile(r"shorewallnf/([A-Za-z0-9_/]+\.py)")


def test_layout_doc_covers_every_pipeline_stage() -> None:
    text = DOC.read_text()
    missing = [s for s in STAGES if s not in text]
    assert not missing, f"module-layout.md omits pipeline stages: {missing}"


def test_modules_marked_present_exist() -> None:
    """Every module the doc marks 'present' must exist under src/shorewallnf/."""
    present: list[str] = []
    for line in DOC.read_text().splitlines():
        if line.lstrip().startswith("|") and "present" in line.lower():
            present.extend(_MODULE.findall(line))
    assert present, "expected at least one module marked 'present' (e.g. ir.py)"
    missing = [m for m in present if not (PKG / m).exists()]
    assert not missing, f"doc marks these 'present' but they are absent: {missing}"
