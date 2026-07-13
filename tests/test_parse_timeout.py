"""Tests for :func:`shorewallnf.applier.parse_timeout` (task #436).

A pure helper that parses a safe-apply timeout argument into whole seconds, accepting a bare
integer (seconds) and the ``Ns``/``Nm``/``Nh`` suffix forms. Malformed input fails fast with a
single :class:`~shorewallnf.errors.ShorewallNFError` naming the offending value (ADR-0004).
"""

from __future__ import annotations

import pytest

from shorewallnf.applier import parse_timeout
from shorewallnf.errors import ShorewallNFError


@pytest.mark.parametrize(
    ("value", "seconds"),
    [
        ("30", 30),
        ("1", 1),
        ("45s", 45),
        ("5m", 300),
        ("2h", 7200),
        ("90m", 5400),
    ],
)
def test_parse_timeout_accepts(value: str, seconds: int) -> None:
    assert parse_timeout(value) == seconds


@pytest.mark.parametrize(
    "value",
    [
        "",  # empty
        "   ",  # whitespace only
        "0",  # zero
        "0s",  # zero with suffix
        "-5",  # negative
        "-5m",  # negative with suffix
        "abc",  # non-numeric
        "1.5m",  # fractional
        "1.5",  # fractional bare
        "5x",  # unknown suffix
        "5M",  # uppercase suffix
        "5H",  # uppercase suffix
        "s",  # bare suffix, no number
        "m",  # bare suffix, no number
        "5 m",  # embedded whitespace
        "+5",  # explicit sign
    ],
)
def test_parse_timeout_rejects(value: str) -> None:
    with pytest.raises(ShorewallNFError) as excinfo:
        parse_timeout(value)
    # The error must name the offending value.
    assert repr(value) in str(excinfo.value) or value in str(excinfo.value)
