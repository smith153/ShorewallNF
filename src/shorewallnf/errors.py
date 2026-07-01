"""Exception hierarchy — the error model (ADR-0004).

Everything ShorewallNF raises deliberately derives from ``ShorewallNFError``, which
the CLI shell catches exactly once. ``ConfigError`` carries source location and renders
``path:line:col: message``. Programming errors are not modeled here: they raise ordinary
exceptions and crash with a traceback. See docs/adr/0004-error-handling.md.
"""

from __future__ import annotations


class ShorewallNFError(Exception):
    """Base for every error ShorewallNF raises on purpose; caught once in the CLI shell."""


class ConfigError(ShorewallNFError):
    """The user's configuration is invalid.

    Carries optional source location; ``str()`` renders ``path:line:col: message``,
    omitting parts that are unknown.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        line: int | None = None,
        col: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.path = path
        self.line = line
        self.col = col

    def __str__(self) -> str:
        if self.path is None:
            return self.message
        prefix = self.path
        if self.line is not None:
            prefix = f"{prefix}:{self.line}"
            if self.col is not None:
                prefix = f"{prefix}:{self.col}"
        return f"{prefix}: {self.message}"
