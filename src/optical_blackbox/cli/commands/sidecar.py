"""Sidecar management commands for .obb v2.0 files.

Enables vendors to create and manage sidecar JSON files for
post-distribution recipient management.
"""

from pathlib import Path

import click

from ...cli.output.console import print_error, print_info, print_success
from ...core.result import Err
from ...sidecar import SidecarGenerator


@click.group("sidecar")
def sidecar_group() -> None:
    """Manage sidecar files for post-distribution updates."""
    pass


@sidecar_group.command("create")
@click.option(
    "--obb-file-id",
    "-i",
    required=True,
    help="Identifier for the .obb file (e.g., model_id or hash)",
)
@click.option(
    "--vendor-id",
    "-v",
    required=True,
    help="Vendor identifier",
)
@click.option(
    "--model-id",
    "-m",
    required=True,
    help="Model identifier",
)
@click.option(
    "--dek-file",
    "-d",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to DEK file (32-byte raw DEK from .obb creation)",
)
@click.option(
    "--platform-keys",
    "-k",
    multiple=True,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to platform public key (PEM). Can be specified multiple times.",
)
@click.option(
    "--platform-names",
    "-n",
    multiple=True,
    help="Optional platform names (must match order of --platform-keys)",
)
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output path for sidecar JSON file",
)
def create_sidecar(
    obb_file_id: str,
    vendor_id: str,
    model_id: str,
    dek_file: Path,
    platform_keys: tuple[Path, ...],
    platform_names: tuple[str, ...],
    output: Path,
) -> None:
    """Create a new sidecar JSON file with initial recipients.
    
    Example:
        obb sidecar create \\
            -i ac254-050-a \\
            -v thorlabs -m AC254-050-A \\
            -d dek.bin \\
            -k platform1.pub -k platform2.pub \\
            -n "Zemax" -n "CODE V" \\
            -o sidecar.json
    """
    # Validate platform names
    if platform_names and len(platform_names) != len(platform_keys):
        print_error("Number of --platform-names must match number of --platform-keys")
        raise click.Abort()
    
    # Read DEK
    try:
        dek = dek_file.read_bytes()
        if len(dek) != 32:
            print_error(f"Invalid DEK size: expected 32 bytes, got {len(dek)}")
            raise click.Abort()
    except OSError as e:
        print_error(f"Failed to read DEK file: {e}")
        raise click.Abort()
    
    # Read platform keys
    recipient_keys = []
    for i, key_path in enumerate(platform_keys):
        try:
            public_key_pem = key_path.read_bytes()
            platform_name = platform_names[i] if platform_names else None
            recipient_keys.append((public_key_pem, platform_name))
        except OSError as e:
            print_error(f"Failed to read platform key {key_path}: {e}")
            raise click.Abort()
    
    print_info(f"Creating sidecar with {len(recipient_keys)} recipient(s)...")
    
    # Create sidecar
    result = SidecarGenerator.create(
        obb_file_id=obb_file_id,
        vendor_id=vendor_id,
        model_id=model_id,
        dek=dek,
        initial_recipients=recipient_keys,
    )
    
    if isinstance(result, Err):
        print_error(f"Failed to create sidecar: {result.error}")
        raise click.Abort()
    
    sidecar = result.value
    
    # Save sidecar
    save_result = SidecarGenerator.save(sidecar, output)
    if isinstance(save_result, Err):
        print_error(f"Failed to save sidecar: {save_result.error}")
        raise click.Abort()
    
    print_success(f"Created sidecar: {output}")
    print_info(f"Recipients: {len(sidecar.recipients)}")


@sidecar_group.command("add-recipient")
@click.argument("sidecar_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--dek-file",
    "-d",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to DEK file (32-byte raw DEK)",
)
@click.option(
    "--platform-key",
    "-k",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to new recipient's public key (PEM)",
)
@click.option(
    "--platform-name",
    "-n",
    help="Optional platform name",
)
def add_recipient(
    sidecar_file: Path,
    dek_file: Path,
    platform_key: Path,
    platform_name: str | None,
) -> None:
    """Add a new recipient to an existing sidecar.
    
    Example:
        obb sidecar add-recipient sidecar.json \\
            -d dek.bin \\
            -k new_platform.pub \\
            -n "New Platform"
    """
    # Load sidecar
    load_result = SidecarGenerator.load(sidecar_file)
    if isinstance(load_result, Err):
        print_error(f"Failed to load sidecar: {load_result.error}")
        raise click.Abort()
    
    sidecar = load_result.value
    
    # Read DEK
    try:
        dek = dek_file.read_bytes()
        if len(dek) != 32:
            print_error(f"Invalid DEK size: expected 32 bytes, got {len(dek)}")
            raise click.Abort()
    except OSError as e:
        print_error(f"Failed to read DEK file: {e}")
        raise click.Abort()
    
    # Read platform key
    try:
        public_key_pem = platform_key.read_bytes()
    except OSError as e:
        print_error(f"Failed to read platform key: {e}")
        raise click.Abort()
    
    print_info("Adding recipient...")
    
    # Add recipient
    result = SidecarGenerator.add_recipient(
        sidecar=sidecar,
        dek=dek,
        public_key_pem=public_key_pem,
        platform_name=platform_name,
    )
    
    if isinstance(result, Err):
        print_error(f"Failed to add recipient: {result.error}")
        raise click.Abort()
    
    updated_sidecar = result.value
    
    # Save updated sidecar
    save_result = SidecarGenerator.save(updated_sidecar, sidecar_file)
    if isinstance(save_result, Err):
        print_error(f"Failed to save sidecar: {save_result.error}")
        raise click.Abort()
    
    print_success("Recipient added")
    print_info(f"Total recipients: {len(updated_sidecar.recipients)}")


@sidecar_group.command("revoke")
@click.argument("sidecar_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--fingerprint",
    "-f",
    required=True,
    help="Platform fingerprint to revoke (64-char hex string)",
)
def revoke_recipient(
    sidecar_file: Path,
    fingerprint: str,
) -> None:
    """Revoke a recipient's access (affects future downloads only).
    
    Example:
        obb sidecar revoke sidecar.json -f a1b2c3d4...
    """
    # Load sidecar
    load_result = SidecarGenerator.load(sidecar_file)
    if isinstance(load_result, Err):
        print_error(f"Failed to load sidecar: {load_result.error}")
        raise click.Abort()
    
    sidecar = load_result.value
    
    print_info(f"Revoking recipient: {fingerprint[:16]}...")
    
    # Revoke recipient
    result = SidecarGenerator.revoke_recipient(sidecar, fingerprint)
    
    if isinstance(result, Err):
        print_error(f"Failed to revoke recipient: {result.error}")
        raise click.Abort()
    
    updated_sidecar = result.value
    
    # Save updated sidecar
    save_result = SidecarGenerator.save(updated_sidecar, sidecar_file)
    if isinstance(save_result, Err):
        print_error(f"Failed to save sidecar: {save_result.error}")
        raise click.Abort()
    
    print_success("Recipient revoked")
    print_info("Note: Cannot revoke access to already-downloaded files (offline decryption)")
