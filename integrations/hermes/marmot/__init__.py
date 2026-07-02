"""Hermes directory-plugin entry point for Marmot."""

from .adapter import register

__all__ = ["register"]
