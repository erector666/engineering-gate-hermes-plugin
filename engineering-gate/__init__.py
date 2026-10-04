"""Engineering Gate Hermes plugin entrypoint."""

from .adapters.hermes import register

__all__ = ["register"]
