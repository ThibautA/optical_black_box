# Contributing to Optical BlackBox

Thank you for your interest in contributing to Optical BlackBox! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Security](#security)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- A GitHub account

### Setting Up Development Environment

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/obb.git
cd obb
```

2. **Create a virtual environment**

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install in development mode**

```bash
pip install -e ".[dev]"
```

4. **Verify installation**

```bash
python -m pytest tests/
```

### Project Structure

```
optical_blackbox/
├── src/optical_blackbox/    # Main package
│   ├── crypto/              # Encryption, signing, key management (ECDH + AES-256-GCM)
│   ├── core/                # Result type, validators, constants
│   ├── formats/             # OBB file format (binary structure, header, payload)
│   ├── models/              # Pydantic data models (metadata)
│   ├── serialization/       # Binary and PEM utilities
│   └── cli/                 # Command-line interface (keygen, create, extract, inspect)
├── tests/                   # Test suite
│   ├── unit/                # Unit tests (mirror src structure)
│   ├── test_roundtrip.py    # Integration tests (byte-for-byte verification)
│   └── conftest.py          # Shared fixtures
├── testdata/                # Sample encrypted files
└── docs/                    # Documentation
```

**Note**: The project now focuses on simple byte-based encryption. Previous modules for parsing optical files (parsers/, optics/, surfaces/) have been removed.

## Development Workflow

### Branching Strategy

- `main` - Stable release branch
- `develop` - Integration branch for features
- `feature/your-feature` - Feature branches
- `fix/bug-description` - Bug fix branches

### Creating a Feature Branch

```bash
git checkout develop
git pull origin develop
git checkout -b feature/your-feature-name
```

### Making Changes

1. Write code following [coding standards](#coding-standards)
2. Add tests for new functionality
3. Update documentation
4. Ensure all tests pass
5. Commit with clear messages

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build/tool changes

**Examples:**

```
feat(crypto): add batch encryption support

Implement multi-file encryption with progress callback.
Add tests for batch operations and error handling.

Closes #42
```

```
fix(crypto): constant-time comparison for signatures

Replace == with secrets.compare_digest() to prevent timing attacks.
```

## Coding Standards

### Python Style

- **PEP 8** compliance (enforced by Ruff)
- **Type hints** on all public APIs
- **Google-style docstrings**
- **Maximum line length**: 100 characters

### Type Checking

All code must pass type checking:

```bash
mypy src/optical_blackbox
```

### Linting

Use Ruff for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

### Docstring Format

Use Google-style docstrings with examples:

```python
def encrypt_file(input_path: Path, platform_key: bytes) -> Result[bytes, CryptoError]:
    """Encrypt a file using ECDH + AES-256-GCM.

    Args:
        input_path: Path to the file to encrypt
        platform_key: Platform's public key for ECDH

    Returns:
        Ok(bytes) with encrypted payload on success, Err(CryptoError) on failure

    Raises:
        FileNotFoundError: If file doesn't exist

    Example:
        >>> result = encrypt_file(Path("design.zmx"), platform_pubkey)
        >>> if result.is_ok():
        ...     encrypted_data = result.unwrap()
    """
```

## Testing

### Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit

# With coverage
pytest --cov=optical_blackbox --cov-report=html

# Specific module
pytest tests/unit/crypto/
```

### Test Coverage Requirements

- **Minimum coverage**: 75% overall
- **New features**: 90%+ coverage required
- **Critical modules** (crypto, formats): 95%+

### Writing Tests

- Use `pytest` fixtures from `tests/conftest.py`
- One test file per module (mirror structure)
- Test classes group related tests
- Descriptive test names: `test_<what>_<condition>_<expected>`

**Example:**

```python
def test_encrypt_with_invalid_key_raises_error(sample_plaintext):
    """Should raise ValueError for wrong key size."""
    invalid_key = b"short"
    
    with pytest.raises(ValueError, match="Key must be 32 bytes"):
        encrypt(sample_plaintext, invalid_key)
```

### Test Organization

```python
class TestFeatureName:
    """Tests for FeatureName functionality."""

    def test_basic_case(self):
        """Should handle basic case."""
        pass

    def test_edge_case(self):
        """Should handle edge case."""
        pass

    def test_error_condition(self):
        """Should raise error for invalid input."""
        pass
```

## Documentation

### Updating Documentation

When adding features or changing APIs:

1. Update docstrings
2. Update `README.md` if CLI changes
3. Update `OPTICAL_BLACKBOX_SPEC.md` if format changes
4. Update `docs/API.md` for new public APIs
5. Add entry to `CHANGELOG.md` (Unreleased section)

### Building Documentation

```bash
# Install docs dependencies
pip install mkdocs mkdocs-material mkdocstrings[python]

# Serve locally
mkdocs serve

# Build static site
mkdocs build
```

## Submitting Changes

### Pull Request Process

1. **Update your branch**

```bash
git checkout develop
git pull origin develop
git checkout feature/your-feature
git rebase develop
```

2. **Run all checks**

```bash
pytest
mypy src/
ruff check src/ tests/
```

3. **Push to your fork**

```bash
git push origin feature/your-feature
```

4. **Create Pull Request**
   - Go to GitHub and create PR from your fork
   - Target the `develop` branch
   - Fill out PR template
   - Link related issues

### PR Title Format

```
<type>: <description>
```

Example: `feat: add batch encryption support`

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] All tests pass
- [ ] Type checking passes
- [ ] Linting passes

## Related Issues
Closes #XX
```

### Review Process

1. Automated checks must pass (tests, linting, type checking)
2. At least one maintainer approval required
3. Address review comments
4. Maintainer will merge when ready

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

See [SECURITY.md](SECURITY.md) for reporting instructions.

### Security Review

Changes to cryptographic code require:
- Extra scrutiny in code review
- Explicit security rationale in PR description
- Additional tests for edge cases and attacks

## Questions?

- **General questions**: Open a [GitHub Discussion](https://github.com/ThibautA/obb/discussions)
- **Bug reports**: Open an [Issue](https://github.com/ThibautA/obb/issues)
- **Feature requests**: Open an [Issue](https://github.com/ThibautA/obb/issues) with `enhancement` label

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Optical BlackBox! 🔒✨
