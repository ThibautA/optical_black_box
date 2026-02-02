# Security Policy

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Model

Optical BlackBox uses industry-standard cryptography to protect lens design data:

### Cryptographic Primitives

- **Elliptic Curve**: NIST P-256 (secp256r1)
- **Key Exchange**: ECDH (Elliptic Curve Diffie-Hellman)
- **Symmetric Encryption**: AES-256-GCM
- **Key Derivation**: HKDF-SHA256
- **Digital Signatures**: ECDSA with P-256

### Security Guarantees

**Confidentiality**
- ✅ Lens design data encrypted with AES-256-GCM
- ✅ Forward secrecy via ephemeral ECDH keys
- ✅ Authenticated encryption (prevents tampering)

**Authenticity**
- ✅ Vendor signatures verify data origin
- ✅ ECDSA prevents signature forgery
- ✅ Platform-specific encryption (only intended recipient can decrypt)

**Integrity**
- ✅ GCM authentication tag prevents modification
- ✅ Signatures cover metadata and encrypted payload
- ✅ File format magic bytes detect corruption

### Threat Model

**Protected Against:**
- Unauthorized decryption of lens data
- Tampering with encrypted files
- Signature forgery
- Man-in-the-middle attacks (if keys distributed securely)
- Accidental exposure (encrypted at rest)

**NOT Protected Against:**
- Compromise of vendor/platform private keys
- Social engineering to obtain keys
- Side-channel attacks on key storage
- Vulnerabilities in Python cryptography dependencies
- Attacks on key distribution mechanisms

### Assumptions

1. **Key Security**: Private keys are stored securely (encrypted at rest, access controlled)
2. **Key Distribution**: Public keys are distributed via trusted channels
3. **Platform Trust**: Platform operators protect their private keys
4. **No Backdoors**: No key escrow or backdoor mechanisms exist

## Reporting a Vulnerability

### DO NOT

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before a fix is available
- Test the vulnerability on production systems you don't own

### DO

**Report security vulnerabilities via email:**

📧 **security@etendue.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if known)
- Your contact information

### Response Timeline

| Stage | Timeline |
|-------|----------|
| **Initial Response** | Within 48 hours |
| **Vulnerability Confirmation** | Within 1 week |
| **Fix Development** | 2-4 weeks (severity dependent) |
| **Security Advisory** | After fix is released |

### Severity Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| **Critical** | Remote code execution, key extraction | 24-48 hours |
| **High** | Encryption bypass, signature forgery | 1 week |
| **Medium** | Information disclosure, DoS | 2 weeks |
| **Low** | Minor information leak | 4 weeks |

## Security Best Practices

### For Vendors (Lens Designers)

1. **Key Management**
   - Generate keys with `obb generate-keypair`
   - Store private keys encrypted at rest
   - Use hardware security modules (HSM) for production
   - Rotate keys annually or after compromise

2. **Encryption**
   - Always verify successful encryption (`obb encrypt` exit code)
   - Include metadata to identify lens designs
   - Test decryption after encryption

3. **Distribution**
   - Share public keys via HTTPS/TLS
   - Verify recipient identity before sharing encrypted files
   - Use secure channels (not email attachments)

### For Platforms (Optical Software)

1. **Key Protection**
   - Store platform private key in secure location
   - Restrict file system permissions (600)
   - Consider TPM/Secure Enclave on supported platforms
   - Log all key access

2. **Decryption**
   - Verify vendor signatures before decryption
   - Maintain allowlist of trusted vendor public keys
   - Log decryption attempts (success/failure)
   - Handle decryption errors gracefully

3. **User Access**
   - Implement access controls for decrypted data
   - Audit lens design usage
   - Clear decrypted data from memory after use

## Known Security Limitations

### MVP (v1.0.0)

1. **Key Distribution**: No built-in PKI or key distribution mechanism
   - Users must distribute public keys out-of-band
   - No certificate authorities or trust chains

2. **Key Rotation**: No automatic key rotation
   - Manual process required
   - Old encrypted files require re-encryption

3. **Revocation**: No key revocation mechanism
   - Compromised keys cannot be revoked automatically
   - Platforms must manually remove public keys

4. **Side Channels**: Limited side-channel protections
   - Timing attacks on signature verification mitigated
   - No protection against power analysis or cache timing

### Future Enhancements

- Certificate-based key distribution (X.509)
- Key revocation lists (CRL)
- Hardware security module (HSM) integration
- Multi-factor authentication for key access
- Automated key rotation

## Security Audits

| Date | Auditor | Scope | Report |
|------|---------|-------|--------|
| 2026-01-15 | Internal | Code review | N/A (pre-release) |

External security audits planned for Q2 2026.

## Cryptography Dependencies

```python
cryptography>=41.0.0  # Python Cryptographic Authority
```

**Supply Chain Security:**
- All dependencies pinned in `requirements.txt`
- Regular updates for security patches
- Vulnerability scanning with `pip-audit`

## Compliance

### Standards Conformance

- **NIST SP 800-56A**: ECDH key agreement
- **NIST SP 800-38D**: GCM mode
- **FIPS 186-4**: ECDSA digital signatures
- **RFC 5869**: HKDF key derivation

### Export Control

Optical BlackBox uses cryptography that may be subject to export controls:
- Check your local regulations before distribution
- US export controls: ECCN 5D002
- EU export controls: Dual-use regulation Category 5

## Acknowledgements

We thank the security research community for responsible disclosure.

### Hall of Fame

(To be populated with security researchers who report vulnerabilities)

---

**Contact:** security@etendue.com  
**PGP Key:** [To be published]

Last updated: February 2, 2026
