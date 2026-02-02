# Optical BlackBox (OBB) Framework - Spécification Technique v1.0

## Vue d'ensemble

Framework open-source permettant aux fabricants d'optiques de distribuer leurs designs sous forme chiffrée ("blackbox") tout en permettant leur utilisation dans des logiciels de simulation optique.

### Architecture Globale

```
┌─────────────────────────────────────────┐      ┌─────────────────────────────────┐
│  OUTIL STANDALONE OPEN-SOURCE           │      │  PLATEFORME (Agent Etendue)     │
│  "optical-blackbox" (PyPI)              │      │                                 │
│                                         │      │                                 │
│  • CLI: obb keygen / create / inspect   │      │  • API PKI: /api/vendors/       │
│  • Parse Zemax .zmx / .zar              │  →   │  • Import fichiers .obb         │
│  • Calcul auto EFL, NA, diamètre        │ .obb │  • Déchiffrement en mémoire     │
│  • Chiffrement ECDH + AES-256-GCM       │      │  • Raytracing SurfaceGroup      │
│  • 100% local, aucune dépendance        │      │  • Géométrie proxy 3D           │
└─────────────────────────────────────────┘      └─────────────────────────────────┘
         CHEZ LE VENDOR                                   PLATEFORME
```

---

## Partie 1: Outil Standalone `optical-blackbox`

### 1.1 Structure du Projet

```
optical-blackbox/
├── src/optical_blackbox/
│   ├── __init__.py
│   ├── cli.py                     # Point d'entrée CLI (Click)
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── keys.py                # Génération/gestion clés ECDSA
│   │   └── encryption.py          # Chiffrement ECDH + AES-256-GCM
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── zemax.py               # Parser .zmx/.zar
│   │   └── surface_extractor.py   # Extraction SurfaceGroup séquentiel
│   ├── models/
│   │   ├── __init__.py
│   │   ├── surface.py             # Modèle Surface
│   │   ├── surface_group.py       # Modèle SurfaceGroup
│   │   └── metadata.py            # Métadonnées publiques
│   ├── formats/
│   │   ├── __init__.py
│   │   └── obb.py                 # Lecture/écriture format .obb
│   └── optics/
│       ├── __init__.py
│       └── paraxial.py            # Calculs EFL, NA, BFL
├── tests/
│   ├── test_crypto.py
│   ├── test_parser.py
│   ├── test_obb_format.py
│   └── fixtures/
│       └── sample.zmx
├── pyproject.toml
├── README.md
└── LICENSE                        # MIT
```

### 1.2 Dépendances (pyproject.toml)

```toml
[project]
name = "optical-blackbox"
version = "1.0.0"
description = "Create encrypted optical component files (.obb) from Zemax designs"
requires-python = ">=3.10"
license = {text = "MIT"}

dependencies = [
    "cryptography>=41.0.0",    # ECDSA, ECDH, AES-GCM
    "click>=8.0.0",            # CLI framework
    "pydantic>=2.0.0",         # Modèles de données
    "numpy>=1.24.0",           # Calculs optiques
    "rich>=13.0.0",            # CLI formatting
]

[project.scripts]
obb = "optical_blackbox.cli:main"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]
```

### 1.3 Commandes CLI

```bash
# Générer une paire de clés vendor
obb keygen --vendor-id thorlabs --output ./keys/
# Crée: thorlabs_private.pem, thorlabs_public.pem

# Créer une blackbox à partir d'un fichier Zemax
obb create \
    --input design.zmx \
    --private-key ./keys/thorlabs_private.pem \
    --platform-key ./platform_public.pem \
    --vendor-id thorlabs \
    --name "AC254-050-A" \
    --output AC254-050-A.obb

# Inspecter les métadonnées publiques (sans déchiffrer)
obb inspect AC254-050-A.obb
# Output:
# Vendor: thorlabs
# Name: AC254-050-A
# EFL: 50.0 mm
# NA: 0.25
# Diameter: 25.4 mm
# Spectral Range: 400-700 nm
# Surfaces: 4
# Created: 2026-01-30T14:32:00Z
# Signature: Valid ✓
```

---

## 1.4 Modèles de Données

### 1.4.1 Surface (src/optical_blackbox/models/surface.py)

```python
from pydantic import BaseModel
from typing import Optional, Dict
from enum import Enum

class SurfaceType(str, Enum):
    STANDARD = "standard"
    EVENASPH = "evenasph"
    ODDASPH = "oddasph"
    TOROIDAL = "toroidal"

class Surface(BaseModel):
    """Surface optique séquentielle."""
    surface_number: int
    surface_type: SurfaceType = SurfaceType.STANDARD
    radius: float  # mm, inf = plat
    thickness: float  # mm, distance à la surface suivante
    material: Optional[str] = None  # None = air
    semi_diameter: float  # mm
    conic: float = 0.0
    
    # Coefficients asphériques (si applicable)
    aspheric_coeffs: Optional[Dict[str, float]] = None
    # Format: {"A2": 0.0, "A4": 1.2e-5, "A6": 3.4e-8, ...}
    
    # Décentralisation/tilt (optionnel)
    decenter_x: float = 0.0
    decenter_y: float = 0.0
    tilt_x: float = 0.0  # degrés
    tilt_y: float = 0.0
    
    class Config:
        json_schema_extra = {
            "example": {
                "surface_number": 1,
                "surface_type": "standard",
                "radius": 25.84,
                "thickness": 6.0,
                "material": "N-BK7",
                "semi_diameter": 12.7,
                "conic": 0.0
            }
        }
```

### 1.4.2 SurfaceGroup (src/optical_blackbox/models/surface_group.py)

```python
from pydantic import BaseModel
from typing import Optional, List, Literal
from .surface import Surface

class SurfaceGroup(BaseModel):
    """Groupe de surfaces séquentielles (élément optique complet)."""
    surfaces: List[Surface]
    stop_surface: Optional[int] = None  # Index de la pupille d'entrée
    
    # Wavelengths de design (pour calcul EFL)
    wavelengths_nm: List[float] = [587.56]  # Défaut: raie d
    primary_wavelength_index: int = 0
    
    # Configuration champ (pour extraction NA)
    field_type: Literal["angle", "height"] = "angle"
    max_field: float = 0.0  # degrés ou mm selon field_type
    
    @property
    def num_surfaces(self) -> int:
        return len(self.surfaces)
    
    @property
    def total_length(self) -> float:
        return sum(s.thickness for s in self.surfaces[:-1])
```

### 1.4.3 Metadata (src/optical_blackbox/models/metadata.py)

```python
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Tuple

class OBBMetadata(BaseModel):
    """Métadonnées publiques (non chiffrées) du fichier .obb"""
    version: str = "1.0"
    vendor_id: str
    name: str
    
    # Propriétés optiques calculées
    efl_mm: float
    na: float
    diameter_mm: float
    spectral_range_nm: Tuple[float, float]
    
    # Infos structurelles
    num_surfaces: int
    
    # Métadonnées fichier
    created_at: Optional[datetime] = None
    
    # Signature ECDSA du payload chiffré (base64)
    signature: str = ""
    
    # Optionnel: infos supplémentaires vendor
    description: Optional[str] = None
    part_number: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "version": "1.0",
                "vendor_id": "thorlabs",
                "name": "AC254-050-A",
                "efl_mm": 50.0,
                "na": 0.25,
                "diameter_mm": 25.4,
                "spectral_range_nm": [400, 700],
                "num_surfaces": 4,
                "created_at": "2026-01-30T14:32:00Z",
                "signature": "MEUCIQD..."
            }
        }
```

---

## 1.5 Module Cryptographique

### 1.5.1 Keys (src/optical_blackbox/crypto/keys.py)

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pathlib import Path
from typing import Optional, Tuple

class KeyManager:
    """Gestion des clés ECDSA P-256."""
    
    CURVE = ec.SECP256R1()
    
    @classmethod
    def generate_keypair(cls) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Génère une nouvelle paire de clés."""
        private_key = ec.generate_private_key(cls.CURVE)
        public_key = private_key.public_key()
        return private_key, public_key
    
    @classmethod
    def save_private_key(
        cls, 
        key: ec.EllipticCurvePrivateKey, 
        path: Path, 
        password: Optional[str] = None
    ):
        """Sauvegarde la clé privée en PEM."""
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption()
        )
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        path.write_bytes(pem)
    
    @classmethod
    def save_public_key(cls, key: ec.EllipticCurvePublicKey, path: Path):
        """Sauvegarde la clé publique en PEM."""
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        path.write_bytes(pem)
    
    @classmethod
    def load_private_key(
        cls, 
        path: Path, 
        password: Optional[str] = None
    ) -> ec.EllipticCurvePrivateKey:
        """Charge une clé privée depuis un fichier PEM."""
        pem = path.read_bytes()
        return serialization.load_pem_private_key(
            pem, 
            password=password.encode() if password else None
        )
    
    @classmethod
    def load_public_key(cls, path: Path) -> ec.EllipticCurvePublicKey:
        """Charge une clé publique depuis un fichier PEM."""
        pem = path.read_bytes()
        return serialization.load_pem_public_key(pem)
    
    @classmethod
    def public_key_to_pem(cls, key: ec.EllipticCurvePublicKey) -> str:
        """Convertit une clé publique en string PEM."""
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
```

### 1.5.2 Encryption (src/optical_blackbox/crypto/encryption.py)

```python
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple

class OBBEncryptor:
    """Chiffrement hybride ECDH + AES-256-GCM pour fichiers .obb"""
    
    NONCE_SIZE = 12  # bytes
    KEY_SIZE = 32    # bytes (AES-256)
    
    @classmethod
    def encrypt(
        cls, 
        plaintext: bytes, 
        recipient_public_key: ec.EllipticCurvePublicKey
    ) -> Tuple[bytes, ec.EllipticCurvePublicKey]:
        """
        Chiffre les données avec ECDH + AES-256-GCM.
        
        Returns:
            (ciphertext, ephemeral_public_key)
        """
        # Générer clé éphémère pour ECDH
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = ephemeral_private.public_key()
        
        # Dériver clé partagée via ECDH
        shared_key = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)
        
        # Dériver clé AES via HKDF
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.KEY_SIZE,
            salt=None,
            info=b"obb-encryption-v1"
        ).derive(shared_key)
        
        # Chiffrer avec AES-256-GCM
        nonce = os.urandom(cls.NONCE_SIZE)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Format: nonce || ciphertext (inclut auth tag)
        encrypted_payload = nonce + ciphertext
        
        return encrypted_payload, ephemeral_public
    
    @classmethod
    def decrypt(
        cls,
        encrypted_payload: bytes,
        ephemeral_public_key: ec.EllipticCurvePublicKey,
        recipient_private_key: ec.EllipticCurvePrivateKey
    ) -> bytes:
        """Déchiffre les données."""
        # Dériver clé partagée via ECDH
        shared_key = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Dériver clé AES via HKDF
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.KEY_SIZE,
            salt=None,
            info=b"obb-encryption-v1"
        ).derive(shared_key)
        
        # Extraire nonce et ciphertext
        nonce = encrypted_payload[:cls.NONCE_SIZE]
        ciphertext = encrypted_payload[cls.NONCE_SIZE:]
        
        # Déchiffrer
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class OBBSigner:
    """Signature ECDSA pour intégrité des fichiers .obb"""
    
    @classmethod
    def sign(cls, data: bytes, private_key: ec.EllipticCurvePrivateKey) -> str:
        """Signe les données et retourne la signature en base64."""
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode()
    
    @classmethod
    def verify(
        cls, 
        data: bytes, 
        signature_b64: str, 
        public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        """Vérifie la signature."""
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
```

---

## 1.6 Format Fichier .obb

### Structure Binaire

```
┌─────────────────────────────────────────────────────────────┐
│ MAGIC BYTES: "OBB\x01" (4 bytes)                            │
├─────────────────────────────────────────────────────────────┤
│ HEADER LENGTH: uint32 little-endian                         │
├─────────────────────────────────────────────────────────────┤
│ HEADER (JSON, UTF-8):                                       │
│   {                                                         │
│     "version": "1.0",                                       │
│     "vendor_id": "thorlabs",                                │
│     "name": "AC254-050-A",                                  │
│     "efl_mm": 50.0,                                         │
│     "na": 0.25,                                             │
│     "diameter_mm": 25.4,                                    │
│     "spectral_range_nm": [400, 700],                        │
│     "num_surfaces": 4,                                      │
│     "created_at": "2026-01-30T...",                         │
│     "signature": "<base64 ECDSA sig of encrypted payload>", │
│     "ephemeral_public_key": "<PEM>"                         │
│   }                                                         │
├─────────────────────────────────────────────────────────────┤
│ ENCRYPTED PAYLOAD (AES-256-GCM):                            │
│   - nonce (12 bytes)                                        │
│   - ciphertext (surfaces JSON chiffré)                      │
│   - auth_tag (16 bytes)                                     │
└─────────────────────────────────────────────────────────────┘
```

### 1.6.1 OBB Format (src/optical_blackbox/formats/obb.py)

```python
import json
import struct
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Tuple

from ..models.metadata import OBBMetadata
from ..models.surface_group import SurfaceGroup
from ..crypto.encryption import OBBEncryptor, OBBSigner

# Magic bytes pour identifier le format
OBB_MAGIC = b"OBB\x01"


class OBBWriter:
    """Écrit un fichier .obb."""
    
    @classmethod
    def write(
        cls,
        output_path: Path,
        surface_group: SurfaceGroup,
        metadata: OBBMetadata,
        vendor_private_key: ec.EllipticCurvePrivateKey,
        platform_public_key: ec.EllipticCurvePublicKey
    ):
        """
        Crée un fichier .obb chiffré.
        
        Args:
            output_path: Chemin du fichier .obb à créer
            surface_group: Données optiques à chiffrer
            metadata: Métadonnées publiques (EFL, NA, etc.)
            vendor_private_key: Clé privée du vendor (pour signature)
            platform_public_key: Clé publique de la plateforme (pour chiffrement)
        """
        # Sérialiser le SurfaceGroup en JSON
        payload_json = surface_group.model_dump_json().encode()
        
        # Chiffrer avec la clé publique de la plateforme
        encrypted_payload, ephemeral_public = OBBEncryptor.encrypt(
            payload_json, 
            platform_public_key
        )
        
        # Signer le payload chiffré avec la clé privée du vendor
        signature = OBBSigner.sign(encrypted_payload, vendor_private_key)
        
        # Mettre à jour les métadonnées avec la signature
        metadata.signature = signature
        metadata.created_at = datetime.utcnow()
        
        # Sérialiser la clé publique éphémère
        ephemeral_pem = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Construire le header
        header = {
            **metadata.model_dump(mode="json"),
            "ephemeral_public_key": ephemeral_pem.decode()
        }
        header_json = json.dumps(header, indent=2).encode()
        
        # Écrire le fichier
        with open(output_path, "wb") as f:
            # Magic bytes
            f.write(OBB_MAGIC)
            
            # Header length (4 bytes, little-endian)
            f.write(struct.pack("<I", len(header_json)))
            
            # Header JSON
            f.write(header_json)
            
            # Encrypted payload
            f.write(encrypted_payload)


class OBBReader:
    """Lit un fichier .obb."""
    
    @classmethod
    def read_metadata(cls, path: Path) -> OBBMetadata:
        """Lit uniquement les métadonnées (sans déchiffrer)."""
        with open(path, "rb") as f:
            # Vérifier magic bytes
            magic = f.read(4)
            if magic != OBB_MAGIC:
                raise ValueError(f"Invalid OBB file: bad magic bytes")
            
            # Lire la taille du header
            header_len = struct.unpack("<I", f.read(4))[0]
            
            # Lire le header
            header_json = f.read(header_len).decode()
            header = json.loads(header_json)
            
            # Retirer la clé éphémère des métadonnées
            header.pop("ephemeral_public_key", None)
            
            return OBBMetadata(**header)
    
    @classmethod
    def read_and_decrypt(
        cls, 
        path: Path, 
        platform_private_key: ec.EllipticCurvePrivateKey,
        vendor_public_key: ec.EllipticCurvePublicKey
    ) -> Tuple[OBBMetadata, SurfaceGroup]:
        """
        Lit et déchiffre un fichier .obb.
        
        Args:
            path: Chemin du fichier .obb
            platform_private_key: Clé privée de la plateforme (pour déchiffrer)
            vendor_public_key: Clé publique du vendor (pour vérifier signature)
            
        Returns:
            (metadata, surface_group)
        """
        with open(path, "rb") as f:
            # Magic bytes
            magic = f.read(4)
            if magic != OBB_MAGIC:
                raise ValueError("Invalid OBB file: bad magic bytes")
            
            # Header
            header_len = struct.unpack("<I", f.read(4))[0]
            header_json = f.read(header_len).decode()
            header = json.loads(header_json)
            
            # Extraire la clé éphémère
            ephemeral_pem = header.pop("ephemeral_public_key").encode()
            ephemeral_public = serialization.load_pem_public_key(ephemeral_pem)
            
            # Payload chiffré
            encrypted_payload = f.read()
        
        # Vérifier la signature
        signature = header.get("signature")
        if not OBBSigner.verify(encrypted_payload, signature, vendor_public_key):
            raise ValueError("Invalid signature: file may be corrupted or tampered")
        
        # Déchiffrer
        payload_json = OBBEncryptor.decrypt(
            encrypted_payload,
            ephemeral_public,
            platform_private_key
        )
        
        # Parser
        metadata = OBBMetadata(**header)
        surface_group = SurfaceGroup.model_validate_json(payload_json)
        
        return metadata, surface_group
```

---

## 1.7 Parser Zemax Simplifié

### src/optical_blackbox/parsers/zemax.py

```python
import re
import zipfile
from pathlib import Path
from typing import Optional, List
from ..models.surface import Surface, SurfaceType
from ..models.surface_group import SurfaceGroup


class ZemaxParser:
    """Parser simplifié pour fichiers Zemax .zmx et .zar"""
    
    # Mapping types de surface Zemax → OBB
    SURFACE_TYPE_MAP = {
        "STANDARD": SurfaceType.STANDARD,
        "EVENASPH": SurfaceType.EVENASPH,
        "ODDASPH": SurfaceType.ODDASPH,
        "TOROIDAL": SurfaceType.TOROIDAL,
    }
    
    @classmethod
    def parse(cls, path: Path) -> SurfaceGroup:
        """Parse un fichier Zemax (.zmx ou .zar)."""
        if path.suffix.lower() == ".zar":
            content = cls._extract_zar(path)
        else:
            content = path.read_text(encoding="utf-16-le", errors="ignore")
        
        return cls._parse_content(content)
    
    @classmethod
    def _extract_zar(cls, path: Path) -> str:
        """Extrait le .zmx d'une archive .zar"""
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.lower().endswith(".zmx"):
                    return zf.read(name).decode("utf-16-le", errors="ignore")
        raise ValueError("No .zmx file found in .zar archive")
    
    @classmethod
    def _parse_content(cls, content: str) -> SurfaceGroup:
        """Parse le contenu d'un fichier .zmx"""
        lines = content.split("\n")
        
        surfaces: List[dict] = []
        wavelengths: List[float] = []
        current_surface: Optional[dict] = None
        stop_surface: Optional[int] = None
        
        for line in lines:
            line = line.strip()
            
            # Nouvelle surface
            if line.startswith("SURF"):
                if current_surface is not None:
                    surfaces.append(current_surface)
                
                parts = line.split()
                surf_num = int(parts[1]) if len(parts) > 1 else 0
                current_surface = {
                    "surface_number": surf_num,
                    "surface_type": SurfaceType.STANDARD,
                    "radius": float("inf"),
                    "thickness": 0.0,
                    "material": None,
                    "semi_diameter": 0.0,
                    "conic": 0.0,
                }
            
            # Propriétés de surface
            elif current_surface is not None:
                parts = line.split()
                if len(parts) < 2:
                    continue
                    
                if line.startswith("TYPE"):
                    type_name = parts[1] if len(parts) > 1 else "STANDARD"
                    current_surface["surface_type"] = cls.SURFACE_TYPE_MAP.get(
                        type_name, SurfaceType.STANDARD
                    )
                elif line.startswith("CURV"):
                    curv = float(parts[1])
                    current_surface["radius"] = 1/curv if curv != 0 else float("inf")
                elif line.startswith("THIC"):
                    current_surface["thickness"] = float(parts[1])
                elif line.startswith("GLAS"):
                    current_surface["material"] = parts[1]
                elif line.startswith("DIAM"):
                    current_surface["semi_diameter"] = float(parts[1])
                elif line.startswith("CONI"):
                    current_surface["conic"] = float(parts[1])
                elif line.startswith("STOP"):
                    stop_surface = current_surface["surface_number"]
                # Coefficients asphériques
                elif line.startswith("PARM"):
                    if len(parts) >= 3:
                        parm_num = int(parts[1])
                        parm_val = float(parts[2])
                        if "aspheric_coeffs" not in current_surface:
                            current_surface["aspheric_coeffs"] = {}
                        current_surface["aspheric_coeffs"][f"A{parm_num*2}"] = parm_val
            
            # Wavelengths
            if line.startswith("WAVM"):
                parts = line.split()
                if len(parts) >= 3:
                    wavelengths.append(float(parts[2]) * 1000)  # µm → nm
        
        # Ajouter la dernière surface
        if current_surface is not None:
            surfaces.append(current_surface)
        
        # Créer les objets Surface
        surface_objects = [Surface(**s) for s in surfaces]
        
        return SurfaceGroup(
            surfaces=surface_objects,
            stop_surface=stop_surface,
            wavelengths_nm=wavelengths if wavelengths else [587.56],
            primary_wavelength_index=0
        )
```

---

## 1.8 Calculs Paraxiaux

### src/optical_blackbox/optics/paraxial.py

```python
import numpy as np
from typing import Dict, Optional
from ..models.surface_group import SurfaceGroup
from ..models.metadata import OBBMetadata

# Indices de réfraction simplifiés (raie d, 587.56 nm)
GLASS_CATALOG: Dict[str, float] = {
    "N-BK7": 1.5168,
    "N-SF11": 1.7847,
    "N-LAK22": 1.6516,
    "N-SK16": 1.6204,
    "F2": 1.6200,
    "SF5": 1.6727,
    "N-SF6": 1.8052,
    "N-LAF2": 1.7440,
    "N-SSK8": 1.6177,
    "N-PSK53A": 1.6180,
    "SILICA": 1.4585,
    "CAF2": 1.4338,
    "SAPPHIRE": 1.7682,
}


def get_refractive_index(material: Optional[str], wavelength_nm: float = 587.56) -> float:
    """Retourne l'indice de réfraction (simplifié, raie d uniquement)."""
    if material is None:
        return 1.0  # Air
    return GLASS_CATALOG.get(material.upper(), 1.5)  # Défaut si inconnu


def compute_paraxial_properties(surface_group: SurfaceGroup) -> Dict[str, float]:
    """
    Calcule les propriétés paraxiales: EFL, BFL, NA.
    
    Utilise le tracé de rayons paraxial matriciel (ABCD).
    """
    wavelength = surface_group.wavelengths_nm[surface_group.primary_wavelength_index]
    
    # Matrice système initialisée à l'identité
    M = np.eye(2)
    
    n_current = 1.0  # Indice initial (air)
    
    for i, surface in enumerate(surface_group.surfaces):
        # Matrice de réfraction
        n_next = get_refractive_index(surface.material, wavelength)
        
        if surface.radius != float("inf") and surface.radius != 0:
            power = (n_next - n_current) / surface.radius
        else:
            power = 0.0
        
        R = np.array([
            [1, 0],
            [-power, n_current / n_next]
        ])
        M = R @ M
        
        # Matrice de transfert (si pas la dernière surface)
        if i < len(surface_group.surfaces) - 1:
            t = surface.thickness
            T = np.array([
                [1, t / n_next],
                [0, 1]
            ])
            M = T @ M
        
        n_current = n_next
    
    # Extraire EFL et BFL de la matrice système
    # M = [[A, B], [C, D]]
    # EFL = -1/C (si C != 0)
    # BFL = -A/C
    A, B = M[0]
    C, D = M[1]
    
    if abs(C) > 1e-10:
        efl = -1.0 / C
        bfl = -A / C
    else:
        efl = float("inf")
        bfl = float("inf")
    
    # NA approximatif (basé sur le diamètre d'entrée et EFL)
    entrance_diameter = surface_group.surfaces[0].semi_diameter * 2
    if abs(efl) > 1e-10 and efl != float("inf"):
        na = entrance_diameter / (2 * abs(efl))
    else:
        na = 0.0
    
    return {
        "efl_mm": round(efl, 4),
        "bfl_mm": round(bfl, 4),
        "na": round(min(na, 1.0), 4),  # Cap à 1.0
    }


def extract_metadata(
    surface_group: SurfaceGroup,
    vendor_id: str,
    name: str,
    description: Optional[str] = None
) -> OBBMetadata:
    """Extrait les métadonnées d'un SurfaceGroup."""
    
    # Calculs paraxiaux
    paraxial = compute_paraxial_properties(surface_group)
    
    # Diamètre max
    max_diameter = max(s.semi_diameter * 2 for s in surface_group.surfaces)
    
    # Plage spectrale
    wl = surface_group.wavelengths_nm
    spectral_range = (min(wl), max(wl))
    
    return OBBMetadata(
        version="1.0",
        vendor_id=vendor_id,
        name=name,
        efl_mm=paraxial["efl_mm"],
        na=paraxial["na"],
        diameter_mm=round(max_diameter, 2),
        spectral_range_nm=spectral_range,
        num_surfaces=surface_group.num_surfaces,
        created_at=None,  # Sera set lors de l'écriture
        signature="",     # Sera set lors de l'écriture
        description=description
    )
```

---

## 1.9 CLI Principal

### src/optical_blackbox/cli.py

```python
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from typing import Optional

from .crypto.keys import KeyManager
from .parsers.zemax import ZemaxParser
from .optics.paraxial import extract_metadata
from .formats.obb import OBBWriter, OBBReader

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def main():
    """Optical BlackBox (OBB) - Create encrypted optical component files."""
    pass


@main.command()
@click.option("--vendor-id", required=True, help="Unique vendor identifier")
@click.option("--output", "-o", type=click.Path(), default=".", help="Output directory")
@click.option("--password", "-p", help="Password to protect private key")
def keygen(vendor_id: str, output: str, password: Optional[str]):
    """Generate a new ECDSA key pair for a vendor."""
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    private_path = output_dir / f"{vendor_id}_private.pem"
    public_path = output_dir / f"{vendor_id}_public.pem"
    
    console.print(f"[bold blue]Generating key pair for vendor:[/] {vendor_id}")
    
    private_key, public_key = KeyManager.generate_keypair()
    
    KeyManager.save_private_key(private_key, private_path, password)
    KeyManager.save_public_key(public_key, public_path)
    
    console.print(f"[green]✓[/] Private key saved to: {private_path}")
    console.print(f"[green]✓[/] Public key saved to: {public_path}")
    console.print()
    console.print("[yellow]⚠ Keep your private key secure! Never share it.[/]")
    console.print("[blue]ℹ Register your public key on the platform to enable imports.[/]")


@main.command()
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True), 
              help="Input Zemax file (.zmx or .zar)")
@click.option("--private-key", "-k", required=True, type=click.Path(exists=True),
              help="Vendor private key file")
@click.option("--platform-key", "-p", required=True, type=click.Path(exists=True),
              help="Platform public key file")
@click.option("--vendor-id", required=True, help="Vendor identifier")
@click.option("--name", "-n", required=True, help="Component name")
@click.option("--description", "-d", help="Optional description")
@click.option("--output", "-o", type=click.Path(), help="Output .obb file path")
@click.option("--key-password", help="Password for private key")
def create(
    input_file: str, 
    private_key: str, 
    platform_key: str,
    vendor_id: str, 
    name: str,
    description: Optional[str],
    output: Optional[str],
    key_password: Optional[str]
):
    """Create an encrypted .obb file from a Zemax design."""
    input_path = Path(input_file)
    private_key_path = Path(private_key)
    platform_key_path = Path(platform_key)
    
    if output:
        output_path = Path(output)
    else:
        output_path = input_path.with_suffix(".obb")
    
    console.print(f"[bold blue]Creating OBB from:[/] {input_path.name}")
    
    # Parser le fichier Zemax
    with console.status("Parsing Zemax file..."):
        surface_group = ZemaxParser.parse(input_path)
    console.print(f"[green]✓[/] Parsed {surface_group.num_surfaces} surfaces")
    
    # Extraire les métadonnées
    with console.status("Computing optical properties..."):
        metadata = extract_metadata(surface_group, vendor_id, name, description)
    console.print(f"[green]✓[/] EFL: {metadata.efl_mm} mm, NA: {metadata.na}")
    
    # Charger les clés
    vendor_private = KeyManager.load_private_key(private_key_path, key_password)
    platform_public = KeyManager.load_public_key(platform_key_path)
    
    # Créer le fichier .obb
    with console.status("Encrypting and signing..."):
        OBBWriter.write(
            output_path,
            surface_group,
            metadata,
            vendor_private,
            platform_public
        )
    
    console.print(f"[green]✓[/] Created: {output_path}")
    console.print()
    
    # Afficher le résumé
    _print_metadata_table(metadata)


@main.command()
@click.argument("file", type=click.Path(exists=True))
def inspect(file: str):
    """Inspect public metadata of an .obb file (without decryption)."""
    path = Path(file)
    
    try:
        metadata = OBBReader.read_metadata(path)
        _print_metadata_table(metadata)
    except Exception as e:
        console.print(f"[red]Error reading file:[/] {e}")


def _print_metadata_table(metadata):
    """Affiche les métadonnées dans un tableau formaté."""
    table = Table(title="OBB Metadata", show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Version", metadata.version)
    table.add_row("Vendor", metadata.vendor_id)
    table.add_row("Name", metadata.name)
    table.add_row("EFL", f"{metadata.efl_mm} mm")
    table.add_row("NA", str(metadata.na))
    table.add_row("Diameter", f"{metadata.diameter_mm} mm")
    table.add_row("Spectral Range", f"{metadata.spectral_range_nm[0]}-{metadata.spectral_range_nm[1]} nm")
    table.add_row("Surfaces", str(metadata.num_surfaces))
    if metadata.created_at:
        table.add_row("Created", metadata.created_at.isoformat())
    table.add_row("Signature", "✓ Present" if metadata.signature else "✗ Missing")
    if metadata.description:
        table.add_row("Description", metadata.description)
    
    console.print(table)


if __name__ == "__main__":
    main()
```

---

## Partie 2: Intégration Plateforme (Agent Etendue)

### 2.1 API PKI - Gestion des Vendors

#### backend/api/vendors/router.py

```python
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, Dict

router = APIRouter(prefix="/api/vendors", tags=["vendors"])


class VendorRegistration(BaseModel):
    vendor_id: str
    public_key_pem: str
    company_name: str
    contact_email: EmailStr
    website: Optional[str] = None


class VendorInfo(BaseModel):
    vendor_id: str
    company_name: str
    public_key_pem: str
    registered_at: datetime
    key_version: int = 1
    is_active: bool = True


# En production: utiliser une vraie DB (PostgreSQL)
# Pour MVP: Redis ou fichier JSON
VENDOR_REGISTRY: Dict[str, VendorInfo] = {}


@router.post("/register", response_model=VendorInfo)
async def register_vendor(registration: VendorRegistration) -> VendorInfo:
    """Enregistre un nouveau vendor avec sa clé publique."""
    if registration.vendor_id in VENDOR_REGISTRY:
        raise HTTPException(400, "Vendor ID already registered")
    
    # Valider que c'est une vraie clé publique ECDSA
    try:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_public_key(registration.public_key_pem.encode())
    except Exception as e:
        raise HTTPException(400, f"Invalid public key: {e}")
    
    vendor = VendorInfo(
        vendor_id=registration.vendor_id,
        company_name=registration.company_name,
        public_key_pem=registration.public_key_pem,
        registered_at=datetime.utcnow(),
    )
    
    VENDOR_REGISTRY[registration.vendor_id] = vendor
    return vendor


@router.get("/{vendor_id}", response_model=VendorInfo)
async def get_vendor(vendor_id: str) -> VendorInfo:
    """Récupère les infos d'un vendor."""
    if vendor_id not in VENDOR_REGISTRY:
        raise HTTPException(404, "Vendor not found")
    return VENDOR_REGISTRY[vendor_id]


@router.get("/{vendor_id}/pubkey")
async def get_vendor_public_key(vendor_id: str) -> dict:
    """Récupère uniquement la clé publique d'un vendor."""
    if vendor_id not in VENDOR_REGISTRY:
        raise HTTPException(404, "Vendor not found")
    return {"public_key_pem": VENDOR_REGISTRY[vendor_id].public_key_pem}


@router.get("/platform/pubkey")
async def get_platform_public_key() -> dict:
    """Récupère la clé publique de la plateforme (pour les vendors)."""
    from ...security.blackbox_keys import get_platform_public_key_pem
    return {"public_key_pem": get_platform_public_key_pem()}
```

### 2.2 Modèle BlackboxComponent

#### backend/models/blackbox.py

```python
from pydantic import BaseModel
from typing import Optional, Tuple
from datetime import datetime


class BlackboxMetadata(BaseModel):
    """Métadonnées publiques d'une blackbox importée."""
    version: str
    vendor_id: str
    name: str
    efl_mm: float
    na: float
    diameter_mm: float
    spectral_range_nm: Tuple[float, float]
    num_surfaces: int
    created_at: datetime
    signature: str
    description: Optional[str] = None


class BlackboxComponent(BaseModel):
    """
    Composant blackbox dans le système optique.
    
    Note: Les surfaces décryptées ne sont JAMAIS stockées dans ce modèle.
    Le décryptage se fait uniquement en mémoire lors du raytracing.
    """
    id: str
    type: str = "blackbox"
    
    # Position dans le système
    position_z: float  # mm depuis l'origine
    
    # Métadonnées publiques (pour affichage)
    metadata: BlackboxMetadata
    
    # Chemin ou contenu du fichier .obb
    obb_file_path: Optional[str] = None
    obb_file_content: Optional[bytes] = None  # Si uploadé directement
    
    # Pour le rendu 3D (géométrie proxy)
    proxy_geometry: Optional[dict] = None
    
    def get_proxy_geometry(self) -> dict:
        """Génère une géométrie proxy simple pour le rendu 3D."""
        # Cylindre simplifié basé sur les métadonnées
        return {
            "type": "cylinder",
            "diameter": self.metadata.diameter_mm,
            "length": self.metadata.efl_mm * 0.2,  # Approximation
            "position_z": self.position_z,
            "label": f"{self.metadata.vendor_id}: {self.metadata.name}",
            "color": "#888888",  # Gris pour indiquer blackbox
        }
```

### 2.3 Loader Blackbox

#### backend/bricks/converters/blackbox_import.py

```python
from pathlib import Path
from typing import TYPE_CHECKING
from cryptography.hazmat.primitives import serialization

# Réutiliser le code de optical-blackbox (installé comme dépendance)
from optical_blackbox.formats.obb import OBBReader
from optical_blackbox.models.surface_group import SurfaceGroup

from ...models.blackbox import BlackboxComponent, BlackboxMetadata
from ...security.blackbox_keys import get_platform_private_key

if TYPE_CHECKING:
    from ...models.elements import SurfaceGroup as PlatformSurfaceGroup


class VendorService:
    """Service pour récupérer les clés publiques des vendors."""
    
    async def get_public_key(self, vendor_id: str) -> str:
        """Récupère la clé publique PEM d'un vendor."""
        # En production: appel DB ou cache
        from ...api.vendors.router import VENDOR_REGISTRY
        if vendor_id not in VENDOR_REGISTRY:
            raise ValueError(f"Unknown vendor: {vendor_id}")
        return VENDOR_REGISTRY[vendor_id].public_key_pem


class BlackboxLoader:
    """
    Charge et déchiffre les fichiers .obb.
    
    IMPORTANT: Le SurfaceGroup décrypté ne doit JAMAIS être:
    - Stocké dans Redis
    - Sérialisé dans une réponse API
    - Persisté dans la DB
    - Loggé
    """
    
    def __init__(self, vendor_service: VendorService):
        self.vendor_service = vendor_service
    
    async def load_metadata(self, obb_path: Path) -> BlackboxMetadata:
        """Charge uniquement les métadonnées (sans décryptage)."""
        metadata = OBBReader.read_metadata(obb_path)
        return BlackboxMetadata(**metadata.model_dump())
    
    async def decrypt_for_raytracing(
        self, 
        obb_path: Path
    ) -> SurfaceGroup:
        """
        Décrypte un .obb pour le raytracing.
        
        Le SurfaceGroup retourné doit être utilisé immédiatement
        puis libéré de la mémoire.
        
        Returns:
            SurfaceGroup décrypté (à utiliser puis détruire)
        """
        # Lire les métadonnées pour obtenir le vendor_id
        metadata = OBBReader.read_metadata(obb_path)
        
        # Récupérer la clé publique du vendor
        vendor_pubkey_pem = await self.vendor_service.get_public_key(metadata.vendor_id)
        vendor_pubkey = serialization.load_pem_public_key(vendor_pubkey_pem.encode())
        
        # Récupérer la clé privée de la plateforme
        platform_private = get_platform_private_key()
        
        # Décrypter
        _, surface_group = OBBReader.read_and_decrypt(
            obb_path,
            platform_private,
            vendor_pubkey
        )
        
        return surface_group
    
    def convert_to_platform_surfaces(
        self, 
        obb_surface_group: SurfaceGroup
    ) -> "PlatformSurfaceGroup":
        """
        Convertit un SurfaceGroup OBB vers le format de la plateforme.
        
        Cette conversion se fait en mémoire uniquement.
        """
        from ...models.elements import SurfaceGroup as PlatformSurfaceGroup
        from ...models.elements import Surface as PlatformSurface
        
        surfaces = []
        for s in obb_surface_group.surfaces:
            surfaces.append(PlatformSurface(
                surface_number=s.surface_number,
                radius=s.radius,
                thickness=s.thickness,
                material=s.material,
                semi_diameter=s.semi_diameter,
                conic=s.conic,
                aspheric_coeffs=s.aspheric_coeffs,
            ))
        
        return PlatformSurfaceGroup(
            surfaces=surfaces,
            stop_surface=obb_surface_group.stop_surface,
        )
```

### 2.4 Gestion des Clés Plateforme

#### backend/security/blackbox_keys/__init__.py

```python
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Optional

# Chemin des clés de la plateforme
KEYS_DIR = Path(__file__).parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "platform_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "platform_public.pem"

_cached_private_key: Optional[ec.EllipticCurvePrivateKey] = None
_cached_public_key: Optional[ec.EllipticCurvePublicKey] = None


def initialize_platform_keys():
    """
    Initialise les clés de la plateforme si elles n'existent pas.
    
    À appeler au démarrage de l'application.
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    
    if not PRIVATE_KEY_PATH.exists():
        # Générer une nouvelle paire de clés
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        # Sauvegarder (en production: utiliser un HSM ou Vault)
        PRIVATE_KEY_PATH.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        
        PUBLIC_KEY_PATH.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        
        print(f"[OBB] Generated new platform keys in {KEYS_DIR}")


def get_platform_private_key() -> ec.EllipticCurvePrivateKey:
    """Retourne la clé privée de la plateforme (cached)."""
    global _cached_private_key
    if _cached_private_key is None:
        if not PRIVATE_KEY_PATH.exists():
            initialize_platform_keys()
        pem = PRIVATE_KEY_PATH.read_bytes()
        _cached_private_key = serialization.load_pem_private_key(pem, password=None)
    return _cached_private_key


def get_platform_public_key() -> ec.EllipticCurvePublicKey:
    """Retourne la clé publique de la plateforme (cached)."""
    global _cached_public_key
    if _cached_public_key is None:
        if not PUBLIC_KEY_PATH.exists():
            initialize_platform_keys()
        pem = PUBLIC_KEY_PATH.read_bytes()
        _cached_public_key = serialization.load_pem_public_key(pem)
    return _cached_public_key


def get_platform_public_key_pem() -> str:
    """Retourne la clé publique en format PEM (pour distribution aux vendors)."""
    if not PUBLIC_KEY_PATH.exists():
        initialize_platform_keys()
    return PUBLIC_KEY_PATH.read_text()
```

---

## Partie 3: Séquence d'Implémentation

### Phase 1: Outil Standalone (2-3 semaines)

| Étape | Tâche | Priorité |
|-------|-------|----------|
| 1.1 | Setup repo `optical-blackbox` + pyproject.toml | P0 |
| 1.2 | Implémenter `crypto/keys.py` et `crypto/encryption.py` | P0 |
| 1.3 | Implémenter les modèles Pydantic (Surface, SurfaceGroup, Metadata) | P0 |
| 1.4 | Implémenter `formats/obb.py` (lecture/écriture) | P0 |
| 1.5 | Implémenter `parsers/zemax.py` (simplifié) | P0 |
| 1.6 | Implémenter `optics/paraxial.py` (calcul EFL/NA) | P1 |
| 1.7 | Implémenter CLI avec Click | P0 |
| 1.8 | Tests unitaires | P0 |
| 1.9 | Documentation README | P1 |
| 1.10 | Publier sur PyPI | P2 |

### Phase 2: Intégration Plateforme (1-2 semaines)

| Étape | Tâche | Priorité |
|-------|-------|----------|
| 2.1 | Créer `backend/api/vendors/` + endpoints PKI | P0 |
| 2.2 | Créer `backend/security/blackbox_keys/` | P0 |
| 2.3 | Créer `backend/models/blackbox.py` | P0 |
| 2.4 | Créer `backend/bricks/converters/blackbox_import.py` | P0 |
| 2.5 | Modifier RaytracingService pour support blackbox | P0 |
| 2.6 | Ajouter rendu proxy 3D (cylindre simplifié) | P1 |
| 2.7 | UI d'import .obb dans le frontend | P1 |
| 2.8 | Tests d'intégration | P0 |

### Phase 3: Polish (1 semaine)

| Étape | Tâche | Priorité |
|-------|-------|----------|
| 3.1 | Page d'enregistrement vendor sur la plateforme | P1 |
| 3.2 | Endpoint public pour télécharger la clé publique plateforme | P0 |
| 3.3 | Gestion rotation de clés | P2 |
| 3.4 | Documentation utilisateur | P1 |

---

## Annexe A: Commandes de Test

```bash
# Installation locale pour dev
cd optical-blackbox
pip install -e .

# Générer clés vendor
obb keygen --vendor-id test-vendor --output ./test-keys/

# Générer clés plateforme (simulé)
obb keygen --vendor-id platform --output ./test-keys/

# Créer une blackbox de test
obb create \
    --input tests/fixtures/doublet.zmx \
    --private-key ./test-keys/test-vendor_private.pem \
    --platform-key ./test-keys/platform_public.pem \
    --vendor-id test-vendor \
    --name "Test Doublet" \
    --output test-doublet.obb

# Inspecter
obb inspect test-doublet.obb
```

---

## Annexe B: Init Files

### src/optical_blackbox/__init__.py

```python
"""Optical BlackBox - Create encrypted optical component files."""

__version__ = "1.0.0"

from .models.surface import Surface, SurfaceType
from .models.surface_group import SurfaceGroup
from .models.metadata import OBBMetadata
from .formats.obb import OBBReader, OBBWriter
from .crypto.keys import KeyManager
from .crypto.encryption import OBBEncryptor, OBBSigner

__all__ = [
    "Surface",
    "SurfaceType", 
    "SurfaceGroup",
    "OBBMetadata",
    "OBBReader",
    "OBBWriter",
    "KeyManager",
    "OBBEncryptor",
    "OBBSigner",
]
```

### src/optical_blackbox/crypto/__init__.py

```python
"""Cryptographic utilities for OBB files."""

from .keys import KeyManager
from .encryption import OBBEncryptor, OBBSigner

__all__ = ["KeyManager", "OBBEncryptor", "OBBSigner"]
```

### src/optical_blackbox/models/__init__.py

```python
"""Data models for optical components."""

from .surface import Surface, SurfaceType
from .surface_group import SurfaceGroup
from .metadata import OBBMetadata

__all__ = ["Surface", "SurfaceType", "SurfaceGroup", "OBBMetadata"]
```

### src/optical_blackbox/parsers/__init__.py

```python
"""Parsers for optical design files."""

from .zemax import ZemaxParser

__all__ = ["ZemaxParser"]
```

### src/optical_blackbox/formats/__init__.py

```python
"""File format handlers."""

from .obb import OBBReader, OBBWriter, OBB_MAGIC

__all__ = ["OBBReader", "OBBWriter", "OBB_MAGIC"]
```

### src/optical_blackbox/optics/__init__.py

```python
"""Optical calculations."""

from .paraxial import compute_paraxial_properties, extract_metadata

__all__ = ["compute_paraxial_properties", "extract_metadata"]
```

---

## Annexe C: README.md pour le repo standalone

```markdown
# Optical BlackBox (OBB)

Create encrypted optical component files (.obb) from Zemax designs for secure distribution.

## Installation

```bash
pip install optical-blackbox
```

## Quick Start

### 1. Generate vendor keys

```bash
obb keygen --vendor-id mycompany --output ./keys/
```

This creates:
- `mycompany_private.pem` - Keep this SECRET
- `mycompany_public.pem` - Register this on the platform

### 2. Get the platform's public key

Download from the platform or use the provided key file.

### 3. Create a blackbox file

```bash
obb create \
    --input my-lens.zmx \
    --private-key ./keys/mycompany_private.pem \
    --platform-key platform_public.pem \
    --vendor-id mycompany \
    --name "MY-LENS-50" \
    --output MY-LENS-50.obb
```

### 4. Inspect metadata (no decryption)

```bash
obb inspect MY-LENS-50.obb
```

## Security Model

- **Vendor Private Key**: Signs the file, proving authenticity
- **Platform Public Key**: Encrypts the optical data
- **Only the platform** can decrypt the optical surfaces
- **Anyone** can verify the signature and read metadata

## License

MIT
```
