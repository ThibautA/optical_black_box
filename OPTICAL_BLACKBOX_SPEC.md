# Optical BlackBox (OBB) - Spécification Technique v2.0

## Vue d'ensemble

Framework open-source permettant aux fabricants d'optiques de distribuer leurs designs optiques sous forme chiffrée tout en permettant leur décryptage par des plateformes autorisées.

**Principe simplifié**: Encrypt raw file bytes → Decrypt → Restore exact original file

---

## Architecture Simplifiée

```
┌─────────────────────────────────────────┐      ┌─────────────────────────────────┐
│  OUTIL STANDALONE                        │      │  PLATEFORME (Agent Etendue)     │
│  "optical-blackbox" (PyPI)              │      │                                 │
│                                         │      │                                 │
│  • CLI: obb keygen / create / extract   │      │  • Import fichiers .obb         │
│  • Lecture fichier brut (bytes)         │  →   │  • Déchiffrement                │
│  • Chiffrement ECDH + AES-256-GCM       │ .obb │  • Restauration fichier original│
│  • Métadonnées minimales                │      │  • Utilisation pour raytracing  │
│  • 100% local, aucune dépendance web    │      │                                 │
└─────────────────────────────────────────┘      └─────────────────────────────────┘
         CHEZ LE VENDOR                                   PLATEFORME
```

---

## 1. Format de Fichier .obb

### 1.1 Structure Binaire

```
┌─────────────────────────────────────────────────────────────────┐
│                         FICHIER .obb                            │
├─────────────────────────────────────────────────────────────────┤
│  [MAGIC: 4 bytes]  "OBB\x01"                                    │
├─────────────────────────────────────────────────────────────────┤
│  [HEADER_LENGTH: 4 bytes]  Length of JSON header                │
├─────────────────────────────────────────────────────────────────┤
│  [HEADER: N bytes]  JSON avec métadonnées publiques            │
├─────────────────────────────────────────────────────────────────┤
│  [ENCRYPTED_PAYLOAD: M bytes]                                   │
│    • [Nonce: 12 bytes]  AES-GCM nonce                          │
│    • [Ciphertext: X bytes]  Fichier chiffré + auth tag        │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Header JSON (Public, non chiffré)

```json
{
  "version": "1.0.0",
  "vendor_id": "acme-optics",
  "model_id": "lens-50mm",
  "created_at": "2026-02-02T15:30:00.123456",
  "description": "50mm imaging lens",
  "original_filename": "lens.zmx",
  "ephemeral_public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**Champs**:
- `version`: Version du format OBB
- `vendor_id`: Identifiant du fabricant (lowercase, alphanumeric + hyphens)
- `model_id`: Identifiant du modèle (lowercase, alphanumeric + hyphens)
- `created_at`: Date/heure de création (ISO 8601)
- `description`: Description optionnelle
- `original_filename`: Nom du fichier original
- `ephemeral_public_key`: Clé publique éphémère pour ECDH (PEM)

### 1.3 Payload Chiffré

Le payload contient les bytes bruts du fichier original chiffrés avec AES-256-GCM.

**Processus**:
1. Génération d'une paire de clés éphémère ECDH (SECP256R1)
2. Dérivation de clé AES-256 via ECDH avec la clé publique de la plateforme
3. Chiffrement AES-256-GCM du fichier brut
4. Stockage: nonce (12 bytes) + ciphertext (avec auth tag 16 bytes)

---

## 2. Cryptographie

### 2.1 ECDH (Elliptic Curve Diffie-Hellman)

**Courbe**: SECP256R1 (NIST P-256)

**Processus d'encryption**:
1. Plateforme génère une paire de clés (private, public)
2. Vendor reçoit la clé publique de la plateforme
3. Pour chaque fichier, vendor génère une paire éphémère
4. Calcul du secret partagé: `ECDH(ephemeral_private, platform_public)`
5. Dérivation de clé AES via HKDF-SHA256

**Processus de decryption**:
1. Lecture de la clé publique éphémère du header
2. Calcul du secret partagé: `ECDH(platform_private, ephemeral_public)`
3. Dérivation de la même clé AES
4. Décryptage du payload

### 2.2 AES-256-GCM

**Paramètres**:
- Mode: GCM (Galois/Counter Mode)
- Taille de clé: 256 bits (32 bytes)
- Nonce: 96 bits (12 bytes) - aléatoire pour chaque fichier
- Tag d'authentification: 128 bits (16 bytes)

**Avantages**:
- Chiffrement + authentification en une seule passe
- Protection contre la modification du ciphertext
- Performance élevée

---

## 3. Commandes CLI

### 3.1 Génération de Clés

```bash
obb keygen OUTPUT_DIR --prefix KEYNAME

# Exemple
obb keygen ./keys --prefix platform

# Génère:
# - platform_private.pem  (secret, pour décrypter)
# - platform_public.pem   (public, pour encrypter)
```

**Options**:
- `OUTPUT_DIR`: Dossier de destination (doit exister)
- `--prefix`: Préfixe des noms de fichiers
- `--force`: Écraser les fichiers existants

### 3.2 Création de Fichier .obb

```bash
obb create INPUT_FILE OUTPUT_FILE \
    -k PLATFORM_PUBLIC_KEY \
    -v VENDOR_ID \
    -m MODEL_ID \
    [-d DESCRIPTION]

# Exemple
obb create lens.zmx lens.obb \
    -k platform_public.pem \
    -v acme-optics \
    -m lens-50mm \
    -d "50mm imaging lens"
```

**Arguments**:
- `INPUT_FILE`: Fichier à chiffrer (n'importe quel format)
- `OUTPUT_FILE`: Fichier .obb de sortie
- `-k, --platform-key`: Clé publique de la plateforme (PEM)
- `-v, --vendor-id`: ID du fabricant (3-50 chars, lowercase alphanumeric + hyphens)
- `-m, --model-id`: ID du modèle (3-50 chars, lowercase alphanumeric + hyphens)
- `-d, --description`: Description optionnelle
- `--force`: Écraser le fichier de sortie s'il existe

### 3.3 Extraction de Fichier .obb

```bash
obb extract INPUT_FILE OUTPUT_FILE \
    -k PLATFORM_PRIVATE_KEY

# Exemple
obb extract lens.obb lens_restored.zmx \
    -k platform_private.pem
```

**Arguments**:
- `INPUT_FILE`: Fichier .obb à décrypter
- `OUTPUT_FILE`: Fichier restauré
- `-k, --platform-key`: Clé privée de la plateforme (PEM)
- `--force`: Écraser le fichier de sortie s'il existe

**Garantie**: Le fichier restauré est **byte-for-byte identique** à l'original.

### 3.4 Inspection de Métadonnées

```bash
obb inspect INPUT_FILE [--json]

# Exemple
obb inspect lens.obb
obb inspect lens.obb --json
```

**Options**:
- `--json`: Sortie au format JSON au lieu de tableau

**Sortie** (sans décryption):
```
                   OBB Metadata                   
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property          ┃ Value                      ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Version           │ 1.0.0                      │
│ Vendor ID         │ acme-optics                │
│ Model ID          │ lens-50mm                  │
│ Description       │ 50mm imaging lens          │
│ Original Filename │ lens.zmx                   │
│ Created           │ 2026-02-02T15:30:00.123456 │
└───────────────────┴────────────────────────────┘
```

---

## 4. API Python

### 4.1 Génération de Clés

```python
from optical_blackbox import KeyManager
from pathlib import Path

# Générer une paire de clés
private_key, public_key = KeyManager.generate_keypair()

# Sauvegarder les clés
KeyManager.save_private_key(private_key, Path("platform_private.pem"))
KeyManager.save_public_key(public_key, Path("platform_public.pem"))

# Charger les clés
private_key = KeyManager.load_private_key(Path("platform_private.pem"))
public_key = KeyManager.load_public_key(Path("platform_public.pem"))
```

### 4.2 Création de Fichier .obb

```python
from optical_blackbox import OBBWriter, OBBMetadata, KeyManager
from pathlib import Path
from datetime import datetime

# Charger la clé publique de la plateforme
platform_public = KeyManager.load_public_key(Path("platform_public.pem"))

# Lire le fichier à chiffrer
input_file = Path("lens.zmx")
file_bytes = input_file.read_bytes()

# Créer les métadonnées
metadata = OBBMetadata(
    version="1.0.0",
    vendor_id="acme-optics",
    model_id="lens-50mm",
    created_at=datetime.utcnow(),
    description="50mm imaging lens",
    original_filename=input_file.name,
)

# Créer le fichier .obb
OBBWriter.write(
    output_path=Path("lens.obb"),
    payload_bytes=file_bytes,
    metadata=metadata,
    platform_public_key=platform_public,
)
```

### 4.3 Extraction de Fichier .obb

```python
from optical_blackbox import OBBReader, KeyManager
from pathlib import Path

# Charger la clé privée de la plateforme
platform_private = KeyManager.load_private_key(Path("platform_private.pem"))

# Lire et décrypter le fichier .obb
metadata, file_bytes = OBBReader.read_and_decrypt(
    path=Path("lens.obb"),
    platform_private_key=platform_private,
)

# Sauvegarder le fichier restauré
Path("lens_restored.zmx").write_bytes(file_bytes)

# Accéder aux métadonnées
print(f"Vendor: {metadata.vendor_id}")
print(f"Model: {metadata.model_id}")
print(f"Original: {metadata.original_filename}")
```

### 4.4 Lecture de Métadonnées Seules

```python
from optical_blackbox import OBBReader
from pathlib import Path

# Lire les métadonnées sans décrypter
metadata = OBBReader.read_metadata(Path("lens.obb"))

print(f"Vendor: {metadata.vendor_id}")
print(f"Model: {metadata.model_id}")
print(f"Description: {metadata.description}")
```

---

## 5. Structure du Code

### 5.1 Organisation des Modules

```
src/optical_blackbox/
├── __init__.py              # API publique
├── cli/                     # Interface ligne de commande
│   ├── main.py              # Point d'entrée CLI
│   ├── commands/
│   │   ├── keygen.py        # Génération de clés
│   │   ├── create.py        # Création .obb
│   │   ├── extract.py       # Extraction .obb
│   │   └── inspect.py       # Inspection métadonnées
│   └── output/
│       ├── console.py       # Formatage console
│       └── formatters.py    # Tables Rich
├── crypto/                  # Cryptographie
│   ├── keys.py              # Gestion clés ECDSA
│   └── ecdh.py              # ECDH + dérivation AES
├── formats/                 # Format .obb
│   ├── obb_file.py          # OBBWriter/OBBReader
│   ├── obb_header.py        # Sérialisation header JSON
│   ├── obb_payload.py       # Encryption/décryption payload
│   └── obb_constants.py     # Magic bytes, constantes
├── models/                  # Modèles de données
│   └── metadata.py          # OBBMetadata (Pydantic)
├── serialization/           # Sérialisation
│   ├── binary.py            # Lecture/écriture binaire
│   └── pem.py               # Conversion clés ↔ PEM
├── core/                    # Utilitaires
│   ├── constants.py         # Constantes globales
│   └── validators.py        # Validation IDs
└── exceptions.py            # Exceptions personnalisées
```

### 5.2 Modèle de Données Principal

```python
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

class OBBMetadata(BaseModel):
    """Métadonnées publiques d'un fichier .obb"""
    
    version: str = Field(default="1.0.0")
    vendor_id: str = Field(min_length=3, max_length=50)
    model_id: str = Field(min_length=3, max_length=50)
    created_at: datetime
    description: str | None = None
    original_filename: str
    
    @field_validator('vendor_id', 'model_id')
    def validate_id_format(cls, v: str) -> str:
        """Valider format: lowercase alphanumeric + hyphens"""
        if not v.replace('-', '').isalnum() or not v.islower():
            raise ValueError("Must be lowercase alphanumeric with hyphens")
        return v
```

---

## 6. Tests

### 6.1 Tests de Roundtrip

```python
def test_roundtrip_bytes():
    """Test que le chiffrement/déchiffrement est parfait"""
    
    # Données originales
    original_bytes = b"Test data" * 100
    
    # Générer clés
    platform_private, platform_public = KeyManager.generate_keypair()
    
    # Chiffrer
    OBBWriter.write(
        output_path=Path("test.obb"),
        payload_bytes=original_bytes,
        metadata=metadata,
        platform_public_key=platform_public,
    )
    
    # Déchiffrer
    _, decrypted_bytes = OBBReader.read_and_decrypt(
        path=Path("test.obb"),
        platform_private_key=platform_private,
    )
    
    # Vérifier
    assert decrypted_bytes == original_bytes
```

### 6.2 Tests avec Fichiers Réels

```python
def test_real_zmx_file():
    """Test avec un vrai fichier .zmx"""
    
    original_file = Path("testdata/lens.zmx")
    original_bytes = original_file.read_bytes()
    
    # Encrypt
    OBBWriter.write(...)
    
    # Decrypt
    _, decrypted_bytes = OBBReader.read_and_decrypt(...)
    
    # Verify byte-for-byte identity
    assert decrypted_bytes == original_bytes
```

---

## 7. Sécurité

### 7.1 Menaces Adressées

| Menace | Protection |
|--------|-----------|
| Lecture du fichier | AES-256-GCM avec clé dérivée ECDH |
| Modification du fichier | Tag d'authentification GCM (16 bytes) |
| Rejeu d'attaque | Clé éphémère unique par fichier |
| Compromission clé plateforme | Seuls les fichiers futurs affectés |

### 7.2 Bonnes Pratiques

**Pour les vendors**:
- Ne jamais partager la clé privée de la plateforme
- Vérifier la clé publique de la plateforme (fingerprint)
- Utiliser `--force` avec précaution

**Pour la plateforme**:
- Protéger la clé privée (HSM, KMS si possible)
- Rotation régulière des clés (migration progressive)
- Audit des accès aux clés

---

## 8. Performance

### 8.1 Overhead de Chiffrement

- **Header**: ~500 bytes (JSON métadonnées + clé éphémère PEM)
- **Nonce**: 12 bytes
- **Auth tag**: 16 bytes
- **Total overhead**: ~530 bytes

**Exemple**: Fichier .zmx de 10 KB → fichier .obb de ~10.5 KB

### 8.2 Vitesse

Sur un processeur moderne:
- **Encryption**: ~500 MB/s
- **Decryption**: ~500 MB/s

---

## 9. Évolutions Futures (Hors MVP)

### 9.1 Fonctionnalités Potentielles

- Signature ECDSA du vendor (authentification)
- Support de multiples clés de plateforme (pour plusieurs destinataires)
- Compression avant chiffrement
- Chiffrement de répertoires complets
- Interface web pour visualisation sécurisée
- Intégration cloud storage (S3, Azure Blob)

### 9.2 Formats Additionnels

- Détection automatique de type de fichier
- Support de formats binaires arbitraires
- Préservation des métadonnées de fichiers système

---

## 10. FAQ

**Q: Puis-je utiliser .obb pour d'autres types de fichiers?**  
R: Oui! L'architecture actuelle chiffre les bytes bruts, donc n'importe quel fichier fonctionne.

**Q: Le fichier décrypté est-il vraiment identique?**  
R: Oui, byte-for-byte. Testé et validé.

**Q: Puis-je avoir plusieurs clés de plateforme?**  
R: Pas dans la version actuelle, mais c'est prévu pour v2.0.

**Q: Que se passe-t-il si je perds la clé privée?**  
R: Les fichiers .obb ne peuvent plus être décryptés. Sauvegardez vos clés!

**Q: La clé éphémère est-elle réutilisée?**  
R: Non, une nouvelle paire éphémère est générée pour chaque fichier.

---

## Annexe A: Format PEM des Clés

### Clé Privée ECDSA P-256

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXoUQDQgAEYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY==
-----END PRIVATE KEY-----
```

### Clé Publique ECDSA P-256

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY==
-----END PUBLIC KEY-----
```

---

## Annexe B: Exemples de Métadonnées

### Exemple Minimal

```json
{
  "version": "1.0.0",
  "vendor_id": "acme",
  "model_id": "lens-001",
  "created_at": "2026-02-02T15:30:00.123456",
  "original_filename": "lens.zmx",
  "ephemeral_public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### Exemple Complet

```json
{
  "version": "1.0.0",
  "vendor_id": "thorlabs-inc",
  "model_id": "ac254-050-a-ml",
  "created_at": "2026-02-02T15:30:00.123456",
  "description": "AC254-050-A-ML - Achromatic Doublet, f=50mm, Ø1\", 400-700nm",
  "original_filename": "AC254-050-A-ML.zmx",
  "ephemeral_public_key": "-----BEGIN PUBLIC KEY-----\nMFkw..."
}
```

---

## Licence

MIT License - Framework open-source pour distribution sécurisée de designs optiques.
