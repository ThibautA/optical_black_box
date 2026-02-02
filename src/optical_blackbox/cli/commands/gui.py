"""GUI command for Optical BlackBox CLI.

Launches the graphical user interface for managing .obb files.
"""

import click


@click.command("gui")
def gui_command() -> None:
    """Launch the Optical BlackBox graphical interface.
    
    Opens a GUI window for creating, extracting, and inspecting .obb files.
    Supports both v1.0 (single recipient) and v2.0 (multi-recipient) formats.
    
    Example:
        obb gui
    """
    try:
        from ...gui import launch_gui
        launch_gui()
    except ImportError as e:
        click.echo(f"Error: GUI dependencies not available: {e}", err=True)
        click.echo("Make sure tkinter is installed (usually included with Python)", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"Error launching GUI: {e}", err=True)
        raise click.Abort()
