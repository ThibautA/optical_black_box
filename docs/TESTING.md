# Guide de Tests - Optical BlackBox

Ce document décrit comment exécuter et maintenir les tests du projet.

## Structure des Tests

```
tests/
├── conftest.py              # Fixtures pytest partagées
├── test_roundtrip.py        # Tests de roundtrip encryption/decryption
└── unit/                    # Tests unitaires
    ├── core/
    ├── crypto/
    ├── formats/
    ├── models/
    └── serialization/
```

## Exécuter les Tests

### Tous les tests

```bash
pytest
```

### Tests avec couverture

```bash
pytest --cov=optical_blackbox --cov-report=html
```

### Tests spécifiques

```bash
# Roundtrip seulement
pytest tests/test_roundtrip.py

# Tests unitaires crypto
pytest tests/unit/crypto/

# Test spécifique
pytest tests/test_roundtrip.py::test_roundtrip_bytes -v
```

## Tests Principaux

### 1. test_roundtrip.py

Tests de bout-en-bout pour vérifier que le chiffrement/déchiffrement fonctionne correctement.

#### test_roundtrip_bytes()
- Crée des données de test
- Chiffre avec une clé
- Déchiffre avec la même clé
- **Vérifie**: Les bytes déchiffrés sont identiques aux originaux

#### test_roundtrip_real_zmx_file()
- Utilise un vrai fichier .zmx du dossier testdata/
- Chiffre le fichier complet
- Déchiffre le fichier
- **Vérifie**: Le fichier restauré est byte-for-byte identique

#### test_metadata_only_read()
- Crée un fichier .obb
- Lit uniquement les métadonnées (sans décryption)
- **Vérifie**: Les métadonnées sont correctes et accessibles sans clé privée

### 2. Tests Unitaires

#### tests/unit/crypto/
- `test_keys.py`: Génération et sérialisation de clés
- `test_ecdh.py`: Dérivation de clés partagées ECDH
- `test_aes_gcm.py`: Chiffrement/déchiffrement AES-GCM

#### tests/unit/formats/
- Écriture/lecture du format .obb
- Sérialisation des headers
- Gestion des erreurs

#### tests/unit/models/
- `test_metadata.py`: Validation du modèle OBBMetadata
- Validation des vendor_id et model_id
- Sérialisation JSON

#### tests/unit/serialization/
- `test_binary.py`: Lecture/écriture binaire
- `test_pem.py`: Conversion clés ↔ PEM

## Fixtures Pytest

Définies dans `conftest.py`:

```python
# Clés cryptographiques
vendor_keypair()        # Paire de clés vendor
platform_keypair()      # Paire de clés platform
platform_private_key()  # Clé privée platform
platform_public_key()   # Clé publique platform
aes_key()              # Clé AES-256 (32 bytes)
aes_nonce()            # Nonce AES-GCM (12 bytes)

# Métadonnées
sample_metadata()      # OBBMetadata de test
```

## Écrire de Nouveaux Tests

### Test de Roundtrip

```python
def test_my_roundtrip():
    # 1. Préparer les données
    original_bytes = Path("testfile.dat").read_bytes()
    
    # 2. Générer les clés
    platform_private, platform_public = KeyManager.generate_keypair()
    
    # 3. Créer métadonnées
    metadata = OBBMetadata(
        version="1.0.0",
        vendor_id="test-vendor",
        model_id="test-model",
        created_at=datetime.utcnow(),
        original_filename="testfile.dat",
    )
    
    # 4. Chiffrer
    with tempfile.NamedTemporaryFile(suffix=".obb") as f:
        obb_path = Path(f.name)
        OBBWriter.write(
            output_path=obb_path,
            payload_bytes=original_bytes,
            metadata=metadata,
            platform_public_key=platform_public,
        )
        
        # 5. Déchiffrer
        _, decrypted_bytes = OBBReader.read_and_decrypt(
            path=obb_path,
            platform_private_key=platform_private,
        )
    
    # 6. Vérifier
    assert decrypted_bytes == original_bytes
```

### Test Unitaire

```python
def test_metadata_validation():
    """Test que les IDs invalides sont rejetés"""
    
    # ID valide (devrait passer)
    metadata = OBBMetadata(
        version="1.0.0",
        vendor_id="valid-vendor",
        model_id="valid-model",
        created_at=datetime.utcnow(),
        original_filename="test.zmx",
    )
    assert metadata.vendor_id == "valid-vendor"
    
    # ID invalide (devrait échouer)
    with pytest.raises(ValueError):
        OBBMetadata(
            version="1.0.0",
            vendor_id="UPPERCASE",  # Pas autorisé
            model_id="valid-model",
            created_at=datetime.utcnow(),
            original_filename="test.zmx",
        )
```

## Tests CLI

Pour tester les commandes CLI:

```bash
# Test manuel des commandes
obb keygen test_keys --prefix test
obb create testdata/Eyepieces/UK565851-1.zmx test.obb -k test_keys/test_public.pem -v test -m test
obb extract test.obb restored.zmx -k test_keys/test_private.pem
obb inspect test.obb

# Vérifier l'identité byte-for-byte (PowerShell)
$original = [System.IO.File]::ReadAllBytes("testdata/Eyepieces/UK565851-1.zmx")
$restored = [System.IO.File]::ReadAllBytes("restored.zmx")
if ((Compare-Object $original $restored) -eq $null) {
    Write-Host "✓ Fichiers identiques" -ForegroundColor Green
} else {
    Write-Host "✗ Fichiers différents" -ForegroundColor Red
}
```

## Couverture de Code

Objectif: **>80%** de couverture

Zones critiques à 100%:
- Chiffrement/déchiffrement (crypto/)
- Lecture/écriture .obb (formats/)
- Modèle de métadonnées (models/metadata.py)

Exclure de la couverture:
- CLI (tests manuels principalement)
- Formatage console (output/)

## Tests de Non-Régression

Après chaque modification:

1. **Exécuter tous les tests**: `pytest`
2. **Vérifier la couverture**: `pytest --cov`
3. **Test CLI manuel**: Créer et extraire un fichier .obb
4. **Vérifier l'identité byte-for-byte** du fichier restauré

## CI/CD (À venir)

Configuration GitHub Actions recommandée:

```yaml
- name: Run tests
  run: |
    pytest --cov=optical_blackbox --cov-report=xml
    
- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Debugging

### Activer les logs détaillés

```bash
pytest -v --log-cli-level=DEBUG
```

### Garder les fichiers temporaires

```python
# Dans le test, utiliser delete=False
with tempfile.NamedTemporaryFile(suffix=".obb", delete=False) as f:
    print(f"Fichier de test: {f.name}")
    # ... test code ...
```

### Inspecter un fichier .obb

```bash
# Voir le header JSON
python -c "
from optical_blackbox.serialization.binary import BinaryReader
with open('test.obb', 'rb') as f:
    reader = BinaryReader(f)
    reader.read_magic()
    header = reader.read_length_prefixed()
    print(header.decode('utf-8'))
"
```

## Données de Test

### testdata/

Le dossier `testdata/` contient des fichiers .zmx réels pour les tests:

```
testdata/
├── Eyepieces/
│   ├── UK565851-1.zmx
│   ├── US01478704-1.zmx
│   └── ...
├── Microscope objectives/
└── Photographic lenses - prime/
```

Ces fichiers sont utilisés pour:
- Tests de roundtrip avec des données réelles
- Validation du support de différents designs optiques
- Tests de performance (taille de fichier)

## Questions Fréquentes

**Q: Les tests sont lents, comment les accélérer?**  
R: Utilisez `pytest -x` pour arrêter au premier échec, ou `pytest -k pattern` pour exécuter un sous-ensemble.

**Q: Comment tester avec mes propres fichiers?**  
R: Ajoutez vos fichiers dans `testdata/` et créez un test similaire à `test_roundtrip_real_zmx_file()`.

**Q: Les tests passent localement mais échouent en CI?**  
R: Vérifiez les chemins de fichiers (utiliser Path), les encodages, et les dépendances système.
