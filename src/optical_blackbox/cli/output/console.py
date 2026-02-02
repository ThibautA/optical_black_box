"""Shared console and styling for CLI output.

Provides a singleton Rich console for consistent output formatting.
"""

from rich.console import Console
from rich.theme import Theme

# Custom theme for OBB CLI
OBB_THEME = Theme({
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "red bold",
    "path": "blue underline",
    "value": "magenta",
    "header": "bold cyan",
    "dim": "dim",
})

# Shared console instance
console = Console(theme=OBB_THEME)


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[success]✓[/success] {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[error]✗[/error] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[warning]⚠[/warning] {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[info]ℹ[/info] {message}")
