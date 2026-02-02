"""CLI commands for Optical BlackBox."""

from optical_blackbox.cli.commands.keygen import keygen_command
from optical_blackbox.cli.commands.create import create_command
from optical_blackbox.cli.commands.extract import extract_command
from optical_blackbox.cli.commands.inspect import inspect_command

__all__ = [
    "keygen_command",
    "create_command",
    "extract_command",
    "inspect_command",
]
