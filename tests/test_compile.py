import json
from pathlib import Path

import pytest

from shorewallnf import cli
from shorewallnf.ir import Family, ZoneMember
from shorewallnf.parser import parse_config
from shorewallnf.preprocessor import SourceLine, to_source_lines

FIXTURE = Path(__file__).parent / "fixtures" / "compile_dir"
GOLDEN = Path(__file__).parent / "golden" / "base_skeleton.json"


def _streams(**files: str) -> dict[str, list[SourceLine]]:
    return {name: to_source_lines(text, name) for name, text in files.items()}


# --- parse_config: assemble the Ruleset --------------------------------------


def test_parse_config_assembles_zones_interfaces_and_membership() -> None:
    ruleset = parse_config(
        _streams(
            zones="fw firewall\nnet ipv4\nloc ipv4\n",
            interfaces="net eth0 detect\nloc eth1 detect\n",
        )
    )
    by_name = {z.name: z for z in ruleset.zones}
    assert by_name["fw"].is_firewall is True
    assert by_name["net"].members == (ZoneMember(interface="eth0", family=Family.BOTH),)
    assert by_name["loc"].members == (ZoneMember(interface="eth1", family=Family.BOTH),)
    assert {i.name for i in ruleset.interfaces} == {"eth0", "eth1"}


def test_parse_config_empty_streams_gives_empty_ruleset() -> None:
    ruleset = parse_config({})
    assert ruleset.zones == () and ruleset.interfaces == ()


# --- compile_config + the compile verb ---------------------------------------


def test_compile_config_emits_base_skeleton() -> None:
    assert cli.compile_config(FIXTURE) == json.loads(GOLDEN.read_text())


def test_compile_verb_emits_json_ruleset(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compile", str(FIXTURE)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted == json.loads(GOLDEN.read_text())


def test_compile_verb_reports_a_missing_config_dir(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compile", "no-such-compile-dir"]) == 1
    assert "error:" in capsys.readouterr().err


# --- nft -c validation (gated on python3-nftables) ---------------------------


def _nft_available() -> bool:
    try:
        import nftables  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(
    not _nft_available(),
    reason="python3-nftables not installed (behavioral netns tier, #77/#78)",
)
def test_generated_ruleset_passes_nft_check() -> None:
    from shorewallnf.applier import check_ruleset

    check_ruleset(cli.compile_config(FIXTURE))  # must not raise
