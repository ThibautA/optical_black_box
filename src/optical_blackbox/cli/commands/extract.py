"""OBB file extraction command.

Decrypts .obb files and extracts the original design file.
"""

from pathlib import Path

import click

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.formats import OBBReader
from optical_blackbox.cli.output.console import console, print_success, print_error, print_info


@click.command("extract")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_file", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--platform-key",
    "-k",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to platform private key (PEM) for decryption",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing output file",
)
def extract_command(
    input_file: Path,
    output_file: Path,
    platform_key: Path,
    force: bool,
) -> None:
    """Extract and decrypt an OBB file.

    Decrypts the .obb file and writes the original optical design
    file exactly as it was before encryption.

    INPUT_FILE: Encrypted .obb file
    OUTPUT_FILE: Output path for decrypted file
    """
    # Check output
    if output_file.exists() and not force:
        print_error(f"Output file exists: {output_file}")
        print_error("Use --force to overwrite")
        raise SystemExit(1)

    # Load platform private key
    print_info("Loading platform key...")
    try:
        platform_private_key = KeyManager.load_private_key(platform_key)
    except Exception as e:
        print_error(f"Failed to load key: {e}")
        raise SystemExit(1)

    # Read and decrypt OBB file
    print_info(f"Decrypting {input_file.name}...")
    try:
        metadata, file_bytes = OBBReader.read_and_decrypt(
            path=input_file,
            platform_private_key=platform_private_key,
        )
    except Exception as e:
        print_error(f"Failed to decrypt: {e}")
        raise SystemExit(1)

    # Write decrypted bytes to output file
    print_info("Writing decrypted file...")
    try:
        output_file.write_bytes(file_bytes)
    except Exception as e:
        print_error(f"Failed to write output: {e}")
        raise SystemExit(1)

    # Get file size
    file_size_kb = len(file_bytes) / 1024

    # Display result
    console.print()
    console.print("[bold green]✓ File Extracted[/bold green]")
    console.print()
    console.print(f"  [dim]Output:[/dim]     {output_file}")
    console.print(f"  [dim]Size:[/dim]       {file_size_kb:.1f} KB")
    console.print(f"  [dim]Vendor:[/dim]     {metadata.vendor_id}")
    console.print(f"  [dim]Model:[/dim]      {metadata.model_id}")
    console.print(f"  [dim]Original:[/dim]   {metadata.original_filename}")
    if metadata.description:
        console.print(f"  [dim]Description:[/dim] {metadata.description}")
    console.print()
    print_success(f"Extracted to {output_file}")
