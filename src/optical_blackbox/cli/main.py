"""Optical BlackBox CLI.

Command-line interface for creating and managing encrypted optical designs.
"""

import click

from optical_blackbox.cli.commands import (
    keygen_command,
    create_command,
    extract_command,
    inspect_command,
    gui_command,
)
from optical_blackbox.cli.commands.create_v2 import create_v2_command
from optical_blackbox.cli.commands.sidecar import sidecar_group


@click.group()
@click.version_option(package_name="optical-blackbox")
def main() -> None:
    """Optical BlackBox - Encrypted optical design distribution.

    Create and manage encrypted .obb files for secure distribution
    of optical designs.

    \b
    Commands:
      keygen      Generate ECDSA P-256 key pair
      create      Create encrypted .obb v1.0 (single recipient)
      create-v2   Create encrypted .obb v2.0 (multi-recipient)
      extract     Decrypt .obb and extract original file
      inspect     View .obb metadata (no decryption)
      sidecar     Manage sidecar files for post-distribution updates
      gui         Launch graphical interface

    \b
    Examples:
      obb keygen ./keys --prefix vendor
      obb create lens.zmx lens.obb -k platform_public.pem -v my-company -m model-1
      obb create-v2 lens.zmx lens.obb -k p1.pub -k p2.pub -v my-company -m model-1
      obb extract lens.obb lens_restored.zmx -k platform_private.pem
      obb inspect lens.obb
    """
    pass


# Register commands
main.add_command(keygen_command, name="keygen")
main.add_command(create_command, name="create")
main.add_command(create_v2_command, name="create-v2")
main.add_command(extract_command, name="extract")
main.add_command(inspect_command, name="inspect")
main.add_command(sidecar_group, name="sidecar")
main.add_command(gui_command, name="gui")


if __name__ == "__main__":
    main()
