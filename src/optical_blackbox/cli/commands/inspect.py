"""OBB file inspection command.

Displays metadata from .obb files without decryption.
"""

from pathlib import Path

import click

from optical_blackbox.formats import OBBReader
from optical_blackbox.cli.output.console import console, print_error
from optical_blackbox.cli.output.formatters import print_metadata


@click.command("inspect")
@click.argument("obb_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output as JSON",
)
def inspect_command(obb_file: Path, as_json: bool) -> None:
    """Inspect metadata from an OBB file.

    OBB_FILE: Path to .obb file
    """
    try:
        metadata = OBBReader.read_metadata(obb_file)
    except Exception as e:
        print_error(f"Failed to read: {e}")
        raise SystemExit(1)

    if as_json:
        # JSON output
        import json
        console.print(json.dumps(metadata.model_dump(), indent=2, default=str))
    else:
        # Rich table output
        print_metadata(metadata)
