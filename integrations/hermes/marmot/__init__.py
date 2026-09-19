"""Hermes directory-plugin entry point for Marmot."""

from typing import Any

__all__ = ["register"]


def __getattr__(name: str) -> Any:
    if name == "register":
        from .adapter import register

        return register
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
