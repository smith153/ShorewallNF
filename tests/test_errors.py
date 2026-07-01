from shorewallnf.errors import ConfigError, ShorewallNFError


def test_config_error_is_a_shorewallnf_error() -> None:
    assert issubclass(ConfigError, ShorewallNFError)


def test_message_only_when_no_location() -> None:
    assert str(ConfigError("boom")) == "boom"


def test_path_only() -> None:
    assert str(ConfigError("boom", path="rules")) == "rules: boom"


def test_path_and_line() -> None:
    assert str(ConfigError("boom", path="rules", line=12)) == "rules:12: boom"


def test_full_location_renders_path_line_col() -> None:
    err = ConfigError("unknown zone 'dmz'", path="rules", line=12, col=5)
    assert str(err) == "rules:12:5: unknown zone 'dmz'"
    assert (err.path, err.line, err.col) == ("rules", 12, 5)
