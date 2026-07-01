"""Reader — the imperative shell that reads a Shorewall config directory.

All filesystem I/O for loading a config lives here (ADR-0003 functional core / imperative
shell): the Reader locates the config directory, discovers the known Shorewall config files
present in it, and hands their raw text to the pure preprocessor/parser core. A missing
directory or file fails fast with :class:`~shorewallnf.errors.ConfigError` carrying the
offending path. See docs/module-layout.md.
"""

from __future__ import annotations

from pathlib import Path

from .errors import ConfigError

# The Shorewall config files ShorewallNF consumes, in processing order. Kept to the MVP
# subset (YAGNI); feature epics extend it as their file parsers land. Discovery filters a
# config directory to these, so unrelated files (``*.bak``, ``shorewall.conf``, READMEs…)
# are ignored.
KNOWN_CONFIG_FILES: tuple[str, ...] = (
    "params",
    "zones",
    "interfaces",
    "policy",
    "rules",
    "snat",
)


def discover(config_dir: str | Path) -> tuple[str, ...]:
    """Return the known Shorewall config files present in ``config_dir``.

    The result preserves :data:`KNOWN_CONFIG_FILES` order and omits files that are absent,
    so callers see only what is there to process. A path that is missing or not a directory
    raises :class:`ConfigError` with that path.
    """
    base = Path(config_dir)
    if not base.is_dir():
        raise ConfigError("not a config directory", path=str(base))
    return tuple(name for name in KNOWN_CONFIG_FILES if (base / name).is_file())


def read_file(config_dir: str | Path, name: str) -> str:
    """Read one config file's text from ``config_dir``.

    A missing directory or file, a non-UTF-8 file, or any other read error raises
    :class:`ConfigError` with the offending file path.
    """
    file_path = Path(config_dir) / name
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError("config file not found", path=str(file_path)) from None
    except UnicodeDecodeError:
        # A mis-encoded config is invalid user input (ADR-0004), not a programming error.
        raise ConfigError("config file is not valid UTF-8", path=str(file_path)) from None
    except OSError as err:
        raise ConfigError(
            f"cannot read config file: {err.strerror or err}", path=str(file_path)
        ) from None
