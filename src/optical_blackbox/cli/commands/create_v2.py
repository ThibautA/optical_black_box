"""OBB v2.0 file creation command with multi-recipient support.

Creates encrypted .obb v2.0 files that can be decrypted by multiple platforms.
"""

from pathlib import Path

import click

from ...cli.output.console import print_error, print_info, print_success
from ...core.result import Err
from ...formats.obb_file_v2 import OBBWriterV2
from ...models.metadata import OBBMetadataV2


@click.command("create-v2")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_file", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--platform-keys",
    "-k",
    multiple=True,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to platform public key (PEM) for encryption. Can be specified multiple times.",
)
@click.option(
    "--platform-names",
    "-n",
    multiple=True,
    help="Optional platform names (must match order of --platform-keys)",
)
@click.option(
    "--vendor-id",
    "-v",
    required=True,
    help="Vendor identifier (3-50 chars)",
)
@click.option(
    "--model-id",
    "-m",
    required=True,
    help="Model identifier (1-100 chars)",
)
@click.option(
    "--description",
    "-d",
    default=None,
    help="Component description (max 500 chars)",
)
@click.option(
    "--sidecar-url",
    "-s",
    default=None,
    help="Optional URL to sidecar JSON for post-distribution updates",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing output file",
)
def create_v2_command(
    input_file: Path,
    output_file: Path,
    platform_keys: tuple[Path, ...],
    platform_names: tuple[str, ...],
    vendor_id: str,
    model_id: str,
    description: str | None,
    sidecar_url: str | None,
    force: bool,
) -> None:
    """Create an encrypted .obb v2.0 file with multi-recipient support.
    
    Example:
        obb create-v2 lens.zmx lens.obb \\
            -k platform1.pub -k platform2.pub \\
            -n "Zemax" -n "CODE V" \\
            -v thorlabs -m AC254-050-A
    """
    # Check output file exists
    if output_file.exists() and not force:
        print_error(f"Output file already exists: {output_file}")
        print_info("Use --force to overwrite")
        raise click.Abort()
    
    # Validate platform names
    if platform_names and len(platform_names) != len(platform_keys):
        print_error("Number of --platform-names must match number of --platform-keys")
        raise click.Abort()
    
    # Read platform public keys
    recipient_keys = []
    for i, key_path in enumerate(platform_keys):
        try:
            public_key_pem = key_path.read_bytes()
            platform_name = platform_names[i] if platform_names else None
            recipient_keys.append((public_key_pem, platform_name))
        except OSError as e:
            print_error(f"Failed to read platform key {key_path}: {e}")
            raise click.Abort()
    
    print_info(f"Creating .obb v2.0 file with {len(recipient_keys)} recipient(s)...")
    
    # Read input file
    try:
        payload_bytes = input_file.read_bytes()
    except OSError as e:
        print_error(f"Failed to read input file: {e}")
        raise click.Abort()
    
    # Create metadata
    metadata = OBBMetadataV2(
        vendor_id=vendor_id,
        model_id=model_id,
        description=description,
        original_filename=input_file.name,
        sidecar_url=sidecar_url,
    )
    
    # Write .obb file
    result = OBBWriterV2.write(
        output_path=output_file,
        payload_bytes=payload_bytes,
        metadata=metadata,
        recipient_public_keys=recipient_keys,
    )
    
    if isinstance(result, Err):
        print_error(f"Failed to create .obb file: {result.error}")
        raise click.Abort()
    
    print_success(f"Created: {output_file}")
    print_info(f"Format: .obb v2.0 (multi-recipient)")
    print_info(f"Recipients: {len(recipient_keys)}")
    print_info(f"Vendor: {vendor_id}")
    print_info(f"Model: {model_id}")
    if sidecar_url:
        print_info(f"Sidecar URL: {sidecar_url}")
