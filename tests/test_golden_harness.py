"""Self-tests for the golden-file snapshot harness (task #114, epic #77)."""

from pathlib import Path

import pytest

import tests.golden_harness as gh
from shorewallnf.ir import Family, Policy, Ruleset, Zone, ZoneMember
from tests.golden_harness import assert_golden


def _rs(action: str = "ACCEPT") -> Ruleset:
    fw = Zone(name="fw", is_firewall=True)
    loc = Zone(name="loc", members=(ZoneMember(interface="eth1", family=Family.BOTH),))
    net = Zone(name="net", members=(ZoneMember(interface="eth0", family=Family.BOTH),))
    return Ruleset(
        zones=(fw, loc, net),
        policies=(Policy(source="loc", dest="net", action=action),),
    )


def test_update_writes_then_compare_matches(tmp_path: Path) -> None:
    rs = _rs()
    assert_golden(rs, "sample", golden_dir=tmp_path, update=True, check_nft=False)
    assert (tmp_path / "sample.json").exists()
    # A subsequent compare of the same ruleset passes.
    assert_golden(rs, "sample", golden_dir=tmp_path, update=False, check_nft=False)


def test_mismatch_raises_with_readable_diff(tmp_path: Path) -> None:
    assert_golden(_rs("ACCEPT"), "sample", golden_dir=tmp_path, update=True, check_nft=False)
    with pytest.raises(AssertionError) as exc:
        assert_golden(_rs("DROP"), "sample", golden_dir=tmp_path, update=False, check_nft=False)
    msg = str(exc.value)
    assert "sample.json" in msg
    assert "accept" in msg and "drop" in msg  # the differing verdict shows in the diff


def test_missing_golden_is_an_error_not_a_silent_pass(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="missing"):
        assert_golden(_rs(), "absent", golden_dir=tmp_path, update=False, check_nft=False)


def test_normal_run_does_not_overwrite_a_wrong_golden(tmp_path: Path) -> None:
    assert_golden(_rs("ACCEPT"), "sample", golden_dir=tmp_path, update=True, check_nft=False)
    fixture = tmp_path / "sample.json"
    original = fixture.read_text()
    with pytest.raises(AssertionError):
        assert_golden(_rs("DROP"), "sample", golden_dir=tmp_path, update=False, check_nft=False)
    assert fixture.read_text() == original  # untouched — update is opt-in


def test_update_defaults_to_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UPDATE_GOLDEN", "1")
    assert_golden(_rs(), "envsample", golden_dir=tmp_path, check_nft=False)
    assert (tmp_path / "envsample.json").exists()


def test_env_var_zero_does_not_enable_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UPDATE_GOLDEN", "0")
    with pytest.raises(AssertionError, match="missing"):
        assert_golden(_rs(), "absent", golden_dir=tmp_path, check_nft=False)


def test_nft_check_skipped_when_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gh, "nft_available", lambda: False)
    monkeypatch.setattr(
        "shorewallnf.applier.check_ruleset",
        lambda _rs: pytest.fail("check_ruleset must not run when nft is unavailable"),
    )
    assert_golden(_rs(), "sample", golden_dir=tmp_path, update=True)  # nft skipped, no error


def test_nft_check_runs_on_rendered_output_when_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(gh, "nft_available", lambda: True)
    monkeypatch.setattr(
        "shorewallnf.applier.check_ruleset", lambda rs: seen.__setitem__("rs", rs)
    )
    out = assert_golden(_rs(), "sample", golden_dir=tmp_path, update=True)
    assert seen["rs"] == out  # the dry-run validated exactly the rendered ruleset
