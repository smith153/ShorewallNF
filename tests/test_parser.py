import dataclasses

import pytest

from shorewallnf.errors import ConfigError
from shorewallnf.parser import Record, parse
from shorewallnf.preprocessor import SourceLine


def _lines(*rows: tuple[str, int, str]) -> list[SourceLine]:
    # rows are (text, line, path)
    return [SourceLine(text=t, path=p, line=n) for (t, n, p) in rows]


def test_splits_fields_on_whitespace_and_keeps_location() -> None:
    lines = _lines(("net     eth1     detect", 19, "interfaces"))
    (record,) = parse(lines)
    assert record.fields == ("net", "eth1", "detect")
    assert (record.path, record.line) == ("interfaces", 19)


def test_splits_on_tabs_and_mixed_whitespace() -> None:
    lines = _lines(("ACCEPT\tnet\tfw\ttcp\t22", 5, "rules"))
    (record,) = parse(lines)
    assert record.fields == ("ACCEPT", "net", "fw", "tcp", "22")


def test_drops_blank_and_full_line_comment_lines() -> None:
    lines = _lines(
        ("# ZONE INTERFACE", 1, "interfaces"),
        ("", 2, "interfaces"),
        ("   ", 3, "interfaces"),
        ("net eth1 detect", 4, "interfaces"),
    )
    records = parse(lines)
    assert len(records) == 1
    assert records[0].fields == ("net", "eth1", "detect")
    assert records[0].line == 4


def test_strips_inline_comment() -> None:
    lines = _lines(("net eth1 detect   # the wan link", 4, "interfaces"))
    (record,) = parse(lines)
    assert record.fields == ("net", "eth1", "detect")


def test_joins_line_continuation_and_records_first_line() -> None:
    lines = _lines(
        ("ACCEPT net fw \\", 10, "rules"),
        ("tcp 22", 11, "rules"),
    )
    (record,) = parse(lines)
    assert record.fields == ("ACCEPT", "net", "fw", "tcp", "22")
    assert record.line == 10  # the record's location is its first physical line


def test_continuation_does_not_glue_adjacent_tokens() -> None:
    lines = _lines(
        ("ACCEPT\\", 1, "rules"),
        ("net", 2, "rules"),
    )
    (record,) = parse(lines)
    assert record.fields == ("ACCEPT", "net")


def test_multiple_records() -> None:
    lines = _lines(
        ("net eth1 detect", 1, "interfaces"),
        ("loc eth0 detect", 2, "interfaces"),
    )
    records = parse(lines)
    assert [r.fields for r in records] == [
        ("net", "eth1", "detect"),
        ("loc", "eth0", "detect"),
    ]


def test_unterminated_continuation_raises_with_location() -> None:
    lines = _lines(("ACCEPT net fw \\", 7, "rules"))
    with pytest.raises(ConfigError) as exc:
        parse(lines)
    assert exc.value.path == "rules"
    assert exc.value.line == 7


def test_record_is_frozen() -> None:
    record = parse(_lines(("net eth1 detect", 1, "interfaces")))[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.fields = ()  # type: ignore[misc]
    assert isinstance(record, Record)
