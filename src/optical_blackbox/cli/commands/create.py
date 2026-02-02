"""OBB file creation command.

Creates encrypted .obb files from optical design files (.zmx, etc).
"""

from pathlib import Path
from datetime import datetime

import click

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.formats import OBBWriter
from optical_blackbox.cli.output.console import console, print_success, print_error, print_info


@click.command("create")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_file", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--platform-key",
    "-k",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to platform public key (PEM) for encryption",
)
@click.option(
    "--vendor-id",
    "-v",
    required=True,
    help="Vendor identifier (3-50 chars, lowercase alphanumeric)",
)
@click.option(
    "--model-id",
    "-m",
    required=True,
    help="Model identifier (3-50 chars, lowercase alphanumeric)",
)
@click.option(
    "--description",
    "-d",
    default=None,
    help="Component description",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing output file",
)
def create_command(
    input_file: Path,
    output_file: Path,
    platform_key: Path,
    vendor_id: str,
    model_id: str,
    description: str | None,
    force: bool,
) -> None:
    """Create an encrypted OBB file from an optical design file.

    Reads the raw bytes from the input file, encrypts them, and
    stores them in an .obb file. The original file can be restored
    exactly during decryption.

    INPUT_FILE: Optical design file (.zmx, .zar, etc)
    OUTPUT_FILE: Output .obb file path
    """
    # Check output
    if output_file.exists() and not force:
        print_error(f"Output file exists: {output_file}")
        print_error("Use --force to overwrite")
        raise SystemExit(1)

    # Ensure .obb extension
    if output_file.suffix.lower() != ".obb":
        output_file = output_file.with_suffix(".obb")

    # Load platform public key
    print_info("Loading platform key...")
    try:
        platform_public_key = KeyManager.load_public_key(platform_key)
    except Exception as e:
        print_error(f"Failed to load key: {e}")
        raise SystemExit(1)

    # Read input file as raw bytes
    print_info(f"Reading {input_file.name}...")
    try:
        payload_bytes = input_file.read_bytes()
        file_size_kb = len(payload_bytes) / 1024
        console.print(f"  [dim]File size: {file_size_kb:.1f} KB ({len(payload_bytes)} bytes)[/dim]")
    except Exception as e:
        print_error(f"Failed to read file: {e}")
        raise SystemExit(1)

    # Create metadata
    metadata = OBBMetadata(
        version="1.0.0",
        vendor_id=vendor_id,
        model_id=model_id,
        created_at=datetime.utcnow(),
        description=description,
        original_filename=input_file.name,
    )

    # Create OBB file
    print_info("Creating encrypted OBB file...")
    try:
        OBBWriter.write(
            output_path=output_file,
            payload_bytes=payload_bytes,
            metadata=metadata,
            platform_public_key=platform_public_key,
        )
    except Exception as e:
        print_error(f"Failed to create OBB file: {e}")
        raise SystemExit(1)

    # Get output file size
    output_size = output_file.stat().st_size
    output_size_kb = output_size / 1024

    # Display result
    console.print()
    console.print("[bold green]✓ OBB File Created[/bold green]")
    console.print()
    console.print(f"  [dim]Output:[/dim]     {output_file}")
    console.print(f"  [dim]Size:[/dim]       {output_size_kb:.1f} KB")
    console.print(f"  [dim]Vendor:[/dim]     {vendor_id}")
    console.print(f"  [dim]Model:[/dim]      {model_id}")
    console.print(f"  [dim]Original:[/dim]   {input_file.name}")
    if description:
        console.print(f"  [dim]Description:[/dim] {description}")
    console.print()
    print_success(f"Created {output_file}")
