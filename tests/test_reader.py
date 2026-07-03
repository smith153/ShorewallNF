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


def test_discover_finds_stoppedrules_when_present(tmp_path: Path) -> None:
    (tmp_path / "zones").write_text("net ipv4\n")
    (tmp_path / "stoppedrules").write_text("ACCEPT net fw tcp 22\n")
    found = discover(tmp_path)
    assert found == ("zones", "stoppedrules")


def test_discover_omits_stoppedrules_when_absent() -> None:
    # The fixture config has no stoppedrules file; it must not appear (omitted cleanly).
    assert "stoppedrules" not in discover(FIXTURE)


def test_discover_missing_directory_raises_with_path() -> None:
    with pytest.raises(ConfigError) as exc:
        discover(FIXTURE / "does-not-exist")
    assert exc.value.path == str(FIXTURE / "does-not-exist")


def test_discover_on_a_file_is_not_a_directory_error() -> None:
    with pytest.raises(ConfigError):
        discover(FIXTURE / "params")


def test_discover_finds_conntrack_file(tmp_path: Path) -> None:
    # The conntrack file (helper assignments) is a known config file (epic #200); it follows
    # snat in processing order.
    (tmp_path / "snat").write_text("MASQUERADE 10.0.0.0/8 eth0\n")
    (tmp_path / "conntrack").write_text("CT:helper:ftp - -\n")
    assert discover(tmp_path) == ("snat", "conntrack")


def test_discover_finds_providers_file(tmp_path: Path) -> None:
    # The providers file (policy routing) is a known config file (epic #204); it follows the
    # interface-defining `interfaces` file so its interface references can be cross-checked (#233).
    (tmp_path / "interfaces").write_text("net eth0 detect\n")
    (tmp_path / "providers").write_text("wan 1 1 eth0 192.0.2.1\n")
    assert discover(tmp_path) == ("interfaces", "providers")


def test_discover_finds_mangle_file(tmp_path: Path) -> None:
    # The mangle file (packet marking) is a known config file (epic #203); it follows conntrack
    # in processing order, grouped with the other packet-processing feature files.
    (tmp_path / "conntrack").write_text("CT:helper:ftp - -\n")
    (tmp_path / "mangle").write_text("MARK(1) net loc\n")
    assert discover(tmp_path) == ("conntrack", "mangle")


def test_discover_finds_action_files_and_index(tmp_path: Path) -> None:
    (tmp_path / "zones").write_text("net ipv4\n")
    (tmp_path / "actions").write_text("Ping\n")
    (tmp_path / "action.Ping").write_text("ACCEPT - - icmp echo-request\n")
    (tmp_path / "action.WebServer").write_text("ACCEPT - - tcp 80\n")
    found = discover(tmp_path)
    # Known files keep their processing order; the actions index and action.<Name>
    # files follow in a stable, sorted order.
    assert found == ("zones", "actions", "action.Ping", "action.WebServer")


def test_discover_action_files_sorted_deterministically(tmp_path: Path) -> None:
    for name in ("action.Zeta", "action.Alpha", "action.Mid"):
        (tmp_path / name).write_text("ACCEPT - -\n")
    assert discover(tmp_path) == ("action.Alpha", "action.Mid", "action.Zeta")


def test_discover_without_action_index_omits_it(tmp_path: Path) -> None:
    (tmp_path / "action.Ping").write_text("ACCEPT - -\n")
    assert discover(tmp_path) == ("action.Ping",)


def test_discover_ignores_action_directory(tmp_path: Path) -> None:
    (tmp_path / "action.Dir").mkdir()
    assert discover(tmp_path) == ()


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


def test_read_file_non_utf8_raises_config_error(tmp_path: Path) -> None:
    # A mis-encoded config is invalid user input (ADR-0004) → ConfigError, not an
    # uncaught UnicodeDecodeError crash.
    (tmp_path / "params").write_bytes(b"NET_IF=\xff\xfe\n")
    with pytest.raises(ConfigError) as exc:
        read_file(tmp_path, "params")
    assert exc.value.path == str(tmp_path / "params")
