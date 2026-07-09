"""Guard: build outputs stay out of the tree.

The MkDocs scaffold (#307) builds to the default `site/` dir; without a
`.gitignore` entry that output shows up as untracked files (#341). This asserts
git ignores it so a `mkdocs build` never dirties the working tree.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_mkdocs_site_dir_is_gitignored() -> None:
    """`git check-ignore site` succeeds — the MkDocs build dir is ignored."""
    result = subprocess.run(
        ["git", "check-ignore", "site"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, "site/ is not gitignored"
    assert result.stdout.strip() == "site"
