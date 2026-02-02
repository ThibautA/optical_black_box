"""Key generation command.

Generates ECDSA P-256 key pairs for OBB signing and encryption.
"""

import hashlib
from pathlib import Path

import click

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.cli.output.console import console, print_success, print_error
from optical_blackbox.cli.output.formatters import format_key_info


@click.command("keygen")
@click.argument("output_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--prefix",
    default="obb",
    help="Prefix for key filenames (default: obb)",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing keys",
)
def keygen_command(output_dir: Path, prefix: str, force: bool) -> None:
    """Generate a new ECDSA P-256 key pair.

    OUTPUT_DIR: Directory to save the keys
    """
    private_path = output_dir / f"{prefix}_private.pem"
    public_path = output_dir / f"{prefix}_public.pem"

    # Check for existing files
    if not force:
        if private_path.exists():
            print_error(f"Private key already exists: {private_path}")
            print_error("Use --force to overwrite")
            raise SystemExit(1)
        if public_path.exists():
            print_error(f"Public key already exists: {public_path}")
            print_error("Use --force to overwrite")
            raise SystemExit(1)

    # Generate keys
    console.print("Generating ECDSA P-256 key pair...", style="dim")

    private_key, public_key = KeyManager.generate_keypair()

    # Save keys
    KeyManager.save_private_key(private_key, private_path)
    KeyManager.save_public_key(public_key, public_path)

    # Compute fingerprint (first 16 hex chars of SHA-256)
    public_pem = public_path.read_text(encoding="ascii")
    fingerprint = hashlib.sha256(public_pem.encode()).hexdigest()[:16].upper()

    # Display results
    console.print()
    console.print(format_key_info("private", str(private_path), fingerprint))
    console.print(format_key_info("public", str(public_path), fingerprint))
    console.print()
    print_success("Key pair generated successfully")
    console.print()
    console.print("[warning]⚠ Keep your private key secure![/warning]")
    console.print("[dim]  Only distribute the public key to users.[/dim]")
