"""RSA-OAEP key wrapping for multi-recipient encryption.

This module provides RSA-OAEP encryption for wrapping Data Encryption Keys (DEKs)
so that multiple recipients can decrypt the same file using their own private keys.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..core.result import Err, Ok, Result
from ..exceptions import DecryptionError, EncryptionError


def wrap_dek(dek: bytes, recipient_public_key: bytes) -> Result[bytes, EncryptionError]:
    """Wrap a Data Encryption Key with RSA-OAEP for a specific recipient.
    
    Args:
        dek: The 32-byte AES-256 key to wrap
        recipient_public_key: PEM-encoded RSA public key
        
    Returns:
        Ok with wrapped DEK bytes, or Err with EncryptionError
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(recipient_public_key)
        if not isinstance(public_key, rsa.RSAPublicKey):
            return Err(EncryptionError("Invalid RSA public key"))
        
        # Wrap DEK using RSA-OAEP with SHA-256
        wrapped = public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return Ok(wrapped)
    
    except Exception as e:
        return Err(EncryptionError(f"Failed to wrap DEK: {e}"))


def unwrap_dek(wrapped_dek: bytes, recipient_private_key: bytes) -> Result[bytes, DecryptionError]:
    """Unwrap a Data Encryption Key using RSA-OAEP.
    
    Args:
        wrapped_dek: The RSA-OAEP encrypted DEK
        recipient_private_key: PEM-encoded RSA private key
        
    Returns:
        Ok with unwrapped 32-byte DEK, or Err with DecryptionError
    """
    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            recipient_private_key,
            password=None,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            return Err(DecryptionError("Invalid RSA private key"))
        
        # Unwrap DEK
        dek = private_key.decrypt(
            wrapped_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        
        if len(dek) != 32:
            return Err(DecryptionError(f"Invalid DEK length: expected 32 bytes, got {len(dek)}"))
        
        return Ok(dek)
    
    except Exception as e:
        return Err(DecryptionError(f"Failed to unwrap DEK: {e}"))


def generate_rsa_keypair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate an RSA key pair for platform use.
    
    Args:
        key_size: RSA key size in bits (default: 2048)
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    return private_pem, public_pem
