import shorewallnf


def test_package_exposes_version() -> None:
    assert isinstance(shorewallnf.__version__, str)
    assert shorewallnf.__version__
