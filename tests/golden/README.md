# Golden fixtures

Expected nftables-JSON snapshots for the golden-file harness (`tests/golden_harness.py`,
epic #77). Each `<name>.json` is the `python3-nftables` JSON that `generate()` emits for a
given IR `Ruleset` — the hermetic, no-root check every feature epic uses.

## Usage

```python
from tests.golden_harness import assert_golden

def test_my_feature() -> None:
    assert_golden(my_ruleset, "my_feature")   # diffs against tests/golden/my_feature.json
```

`assert_golden` renders the ruleset, diffs it against `<name>.json` (a readable unified diff on
mismatch), and — where `python3-nftables` is installed — dry-run validates the output with
`nft -c` (skipped cleanly when absent; pass `check_nft=False` to opt out).

## Conventions

- One file per snapshot, named `<name>.json`, matching the `name` passed to `assert_golden`.
- Formatted as 2-space-indented JSON with a trailing newline (what the update workflow writes).
- Comparison is on parsed JSON, so hand-formatting differences never cause spurious failures.

## Updating on purpose

Fixtures are never rewritten by a normal run. Regenerate them deliberately after an intended
change:

```bash
UPDATE_GOLDEN=1 python -m pytest tests/    # rewrites the goldens the run touches
git diff tests/golden/                     # review the change before committing
```
