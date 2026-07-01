import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_python_floor_is_consistent() -> None:
    """The minimum Python version (3.11) must be declared consistently.

    Guards against drift between the places the floor is stated. See
    docs/adr/0003-design-approach.md.
    """
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["requires-python"] == ">=3.11"
    assert pyproject["tool"]["ruff"]["target-version"] == "py311"
    assert pyproject["tool"]["mypy"]["python_version"] == "3.11"

    ci_lines = (ROOT / ".github" / "workflows" / "ci.yml").read_text().splitlines()
    version_lines = [line for line in ci_lines if "python-version" in line]
    assert version_lines and all('"3.11"' in line for line in version_lines)
