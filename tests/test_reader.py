from pathlib import Path

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.reader import discover, read_file

FIXTURE = Path(__file__).parent / "fixtures" / "config"


# --- discover ---------------------------------------------------------------


def test_discover_returns_known_files_present() -> None:
    assert discover(FIXTURE) == ("params", "zones", "interfaces")


def test_discover_ignores_noise_files() -> None:
    found = discover(FIXTURE)
    assert "README.txt" not in found
    assert "zones.bak" not in found
    assert "shorewall.conf" not in found


def test_discover_missing_directory_raises_with_path() -> None:
    with pytest.raises(ConfigError) as exc:
        discover(FIXTURE / "does-not-exist")
    assert exc.value.path == str(FIXTURE / "does-not-exist")


def test_discover_on_a_file_is_not_a_directory_error() -> None:
    with pytest.raises(ConfigError):
        discover(FIXTURE / "params")


# --- read_file --------------------------------------------------------------


def test_read_file_loads_text() -> None:
    assert read_file(FIXTURE, "params") == "NET_IF=eth1\n"


def test_read_file_missing_file_raises_with_path() -> None:
    with pytest.raises(ConfigError) as exc:
        read_file(FIXTURE, "policy")
    assert exc.value.path == str(FIXTURE / "policy")


def test_read_file_missing_directory_raises_with_path() -> None:
    with pytest.raises(ConfigError) as exc:
        read_file(FIXTURE / "nope", "params")
    assert exc.value.path == str(FIXTURE / "nope" / "params")
