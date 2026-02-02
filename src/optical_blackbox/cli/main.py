"""Optical BlackBox CLI.

Command-line interface for creating and managing encrypted optical designs.
"""

import click

from optical_blackbox.cli.commands import (
    keygen_command,
    create_command,
    extract_command,
    inspect_command,
)


@click.group()
@click.version_option(package_name="optical-blackbox")
def main() -> None:
    """Optical BlackBox - Encrypted optical design distribution.

    Create and manage encrypted .obb files for secure distribution
    of optical designs.

    \b
    Commands:
      keygen   Generate ECDSA P-256 key pair
      create   Create encrypted .obb from optical design file
      extract  Decrypt .obb and extract original file
      inspect  View .obb metadata (no decryption)

    \b
    Examples:
      obb keygen ./keys --prefix vendor
      obb create lens.zmx lens.obb -k platform_public.pem -v my-company -m model-1
      obb extract lens.obb lens_restored.zmx -k platform_private.pem
      obb inspect lens.obb
    """
    pass


# Register commands
main.add_command(keygen_command, name="keygen")
main.add_command(create_command, name="create")
main.add_command(extract_command, name="extract")
main.add_command(inspect_command, name="inspect")


if __name__ == "__main__":
    main()
