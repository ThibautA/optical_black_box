"""Sidecar module initialization."""

from .generator import SidecarGenerator
from .fetcher import fetch_sidecar

__all__ = ["SidecarGenerator", "fetch_sidecar"]
