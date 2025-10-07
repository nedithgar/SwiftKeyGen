# Integration Test Coverage TODO

This document tracks missing integration tests for complete bidirectional interoperability with OpenSSH's `ssh-keygen`. The goal is to ensure SwiftKeyGen can seamlessly read/write keys, certificates, and formats that `ssh-keygen` produces, and vice versa.

## ✅ Current Coverage

### SSHKeygenIntegrationTests.swift
- [x] ssh-keygen can decrypt our encrypted PEM (SEC1) format
- [x] ssh-keygen can decrypt our encrypted PKCS8 format
- [x] Compare format structures (PEM/PKCS8 headers and encryption)
- [x] All PEM cipher compatibility (AES-128-CBC, AES-256-CBC, DES-EDE3-CBC)
- [x] Public key consistency between implementations

### CertificateSSHKeygenIntegrationTests.swift
- [x] ssh-keygen verifies our Ed25519 CA-signed certificates
- [x] ssh-keygen verifies our RSA CA-signed certificates (rsa-sha2-512)
- [x] ssh-keygen verifies our ECDSA P-256 CA-signed certificates
- [x] ssh-keygen verifies our ECDSA P-384 CA-signed certificates
- [x] ssh-keygen verifies our ECDSA P-521 CA-signed certificates

## 🔴 HIGH PRIORITY - Core Interoperability

### OpenSSH Format Bidirectional (CRITICAL)
- [x] **Parse ssh-keygen's OpenSSH format Ed25519 keys** (unencrypted)
- [x] **Parse ssh-keygen's OpenSSH format Ed25519 keys** (encrypted with passphrase)
- [x] **Parse ssh-keygen's OpenSSH format RSA keys** (2048, 3072, 4096 bits)
- [x] **Parse ssh-keygen's OpenSSH format ECDSA keys** (P-256, P-384, P-521)
- [x] **ssh-keygen extracts public key from our OpenSSH format** (all key types)
- [x] **ssh-keygen can decrypt our OpenSSH format** (encrypted keys)
- [x] **Round-trip test**: Generate with ssh-keygen → Parse with us → Export → ssh-keygen reads

### Fingerprint Matching (CRITICAL)
- [x] **SHA256 fingerprints match ssh-keygen** (Ed25519, RSA, ECDSA)
- [x] **SHA512 fingerprints match ssh-keygen** (all key types)
- [x] **MD5 fingerprints match ssh-keygen** (legacy format with colons)
- [x] **Fingerprint format consistency** (Base64 encoding, prefix handling)
- [x] **Fingerprint from different sources** (private key, public key, certificate)

### Parse ssh-keygen Generated Keys (CRITICAL)
- [x] **Parse ssh-keygen Ed25519 private key** (OpenSSH format, no passphrase)
- [x] **Parse ssh-keygen Ed25519 private key** (with passphrase)
- [x] **Parse ssh-keygen RSA private keys** (2048, 3072, 4096 bits, no passphrase)
- [x] **Parse ssh-keygen RSA private keys** (with passphrase)
- [x] **Parse ssh-keygen ECDSA P-256 private key** (no passphrase)
- [x] **Parse ssh-keygen ECDSA P-384 private key** (no passphrase)
- [x] **Parse ssh-keygen ECDSA P-521 private key** (no passphrase)
- [x] **Parse ssh-keygen ECDSA keys** (with passphrase)
- [x] **Extract correct public key from ssh-keygen private keys**
- [x] **Preserve key comments from ssh-keygen**

### Parse ssh-keygen Certificates (CRITICAL)
- [x] **Parse ssh-keygen signed user certificate** (Ed25519 CA)
- [x] **Parse ssh-keygen signed user certificate** (RSA CA with rsa-sha2-256)
- [x] **Parse ssh-keygen signed user certificate** (RSA CA with rsa-sha2-512)
- [x] **Parse ssh-keygen signed user certificate** (ECDSA P-256 CA)
- [x] **Parse ssh-keygen signed user certificate** (ECDSA P-384 CA)
- [x] **Parse ssh-keygen signed user certificate** (ECDSA P-521 CA)
- [x] **Parse ssh-keygen signed host certificate** (all CA types)
- [x] **Verify signature on ssh-keygen certificate** (all CA types)
- [x] **Extract all certificate fields correctly** (principals, validity, serial, options, extensions)
- [x] **Parse certificates with critical options** (force-command, source-address)
- [x] **Parse certificates with custom extensions**

### RFC4716 Format Bidirectional
- [x] **Parse ssh-keygen RFC4716 public key** (Ed25519)
- [x] **Parse ssh-keygen RFC4716 public key** (RSA)
- [x] **Parse ssh-keygen RFC4716 public key** (ECDSA all curves)
- [x] **Parse ssh-keygen RFC4716 with headers** (Comment, Subject, etc.)
- [x] **ssh-keygen reads our RFC4716 format** (all key types)
- [x] **ssh-keygen preserves our RFC4716 headers**
- [x] **Round-trip RFC4716 conversion** (ssh-keygen → us → ssh-keygen)

## 🟡 MEDIUM PRIORITY - Important Features

### Signature Verification Bidirectional
- [x] **Verify ssh-keygen RSA signature** (ssh-rsa with SHA1)
- [x] **Verify ssh-keygen RSA signature** (rsa-sha2-256)
- [x] **Verify ssh-keygen RSA signature** (rsa-sha2-512)
- [x] **Verify ssh-keygen ECDSA P-256 signature** (ecdsa-sha2-nistp256)
- [x] **Verify ssh-keygen ECDSA P-384 signature** (ecdsa-sha2-nistp384)
- [x] **Verify ssh-keygen ECDSA P-521 signature** (ecdsa-sha2-nistp521)
- [x] **Verify ssh-keygen Ed25519 signature** (ssh-ed25519)
- [x] **ssh-keygen verifies our signatures** (via certificate trust chain)
- [x] **Signature verification with message data** (arbitrary payloads)

### Randomart Visualization
- [x] **Randomart matches ssh-keygen for same key** (Ed25519)
- [x] **Randomart matches ssh-keygen for same key** (RSA)
- [x] **Randomart matches ssh-keygen for same key** (ECDSA)
- [x] **Randomart visual structure identical** (border, dimensions, symbols)
- [x] **Randomart deterministic for same input**

### Host Certificates
- [x] **ssh-keygen verifies our host certificate** (Ed25519 CA)
- [x] **ssh-keygen verifies our host certificate** (RSA CA)
- [x] **ssh-keygen verifies our host certificate** (ECDSA CA)
- [x] **We verify ssh-keygen host certificate** (all CA types)
- [x] **Host certificate with wildcard principals**
- [x] **Host certificate validity checks**

### Passphrase Operations Bidirectional
- [x] **ssh-keygen changes passphrase on our OpenSSH key**
- [x] **ssh-keygen removes passphrase from our OpenSSH key**
- [x] **ssh-keygen adds passphrase to our unencrypted OpenSSH key**
- [ ] **ssh-keygen changes passphrase on our PEM key**
- [ ] **ssh-keygen changes passphrase on our PKCS8 key**
- [x] **We change passphrase on ssh-keygen OpenSSH key** (if KeyManager supports)
- [x] **We remove passphrase from ssh-keygen key** (if KeyManager supports)
- [x] **Passphrase operation preserves key integrity**

### Bubble Babble Format
- [x] **Bubble babble matches ssh-keygen** (Ed25519)
- [x] **Bubble babble matches ssh-keygen** (RSA)
- [x] **Bubble babble matches ssh-keygen** (ECDSA all curves)
- [x] **Bubble babble format structure** (hyphen separation, vowel-consonant pattern)

## 🟢 LOWER PRIORITY - Completeness

### Known Hosts Interoperability
- [ ] **Parse ssh-keygen known_hosts entries** (plain hostname)
- [ ] **Parse ssh-keygen known_hosts entries** (hashed hostname)
- [ ] **Parse ssh-keygen known_hosts entries** (IP addresses)
- [ ] **Parse ssh-keygen known_hosts entries** (hostname patterns)
- [ ] **ssh-keygen reads our known_hosts format**
- [ ] **Hashed hostname compatibility** (HMAC-SHA1 format)
- [ ] **known_hosts entry verification** (key matching)
- [ ] **known_hosts hostname hashing bidirectional**

### Large and Edge-Case Key Sizes
- [ ] **ssh-keygen reads our RSA 8192-bit key**
- [ ] **We read ssh-keygen RSA 16384-bit key**
- [ ] **ssh-keygen reads our arbitrary RSA key sizes** (1536, 2560, etc.)
- [ ] **Minimum key size handling** (1024-bit RSA)
- [ ] **Performance test for large keys** (generation and parsing)

### Certificate Advanced Features
- [ ] **Certificate with force-command critical option**
- [ ] **Certificate with source-address restriction** (IPv4)
- [ ] **Certificate with source-address restriction** (IPv6)
- [ ] **Certificate with source-address restriction** (CIDR notation)
- [ ] **Certificate with verify-required option**
- [ ] **Certificate with no-presence-required option**
- [ ] **Certificate with custom extensions** (non-standard)
- [ ] **Certificate extension permit-X11-forwarding**
- [ ] **Certificate extension permit-agent-forwarding**
- [ ] **Certificate extension permit-port-forwarding**
- [ ] **Certificate extension permit-pty**
- [ ] **Certificate extension permit-user-rc**
- [ ] **Multiple principals handling**
- [ ] **Empty principals list** (wildcard access)
- [ ] **Certificate serial number handling** (large values)

### Certificate Validity Edge Cases
- [ ] **Expired certificate handling** (past valid_before)
- [ ] **Not-yet-valid certificate handling** (future valid_after)
- [ ] **Certificate valid for exactly 1 second**
- [ ] **Certificate with forever validity** (0xFFFFFFFFFFFFFFFF)
- [ ] **Certificate validity boundary conditions**

### Format Edge Cases
- [ ] **Keys with unusual comments** (Unicode, special characters)
- [ ] **Keys with very long comments** (>255 characters)
- [ ] **Keys with no comment**
- [ ] **Public key with extra whitespace** (leading, trailing, multiple spaces)
- [ ] **Public key with tabs instead of spaces**
- [ ] **Public key wrapped across multiple lines** (RFC4716)
- [ ] **Malformed key handling** (truncated base64, invalid type)
- [ ] **Mixed line endings** (CRLF vs LF)

### Error Handling Parity
- [ ] **Both reject keys with wrong passphrase** (same error behavior)
- [ ] **Both reject malformed base64 encoding**
- [ ] **Both reject invalid key type identifiers**
- [ ] **Both reject certificates with invalid signatures**
- [ ] **Both reject expired certificates** (same error message/code)
- [ ] **Both handle corrupted key files** (similar recovery or failure)

### Format Conversion Round-Trips
- [ ] **OpenSSH → PEM → OpenSSH** (via both tools)
- [ ] **OpenSSH → PKCS8 → OpenSSH** (via both tools)
- [ ] **PEM → PKCS8 → PEM** (via both tools)
- [ ] **OpenSSH → RFC4716 → OpenSSH** (public key only)
- [ ] **All conversions preserve public key integrity**

## 📁 Suggested Test File Organization

```
Tests/SwiftKeyGenTests/Integration/
├── SSHKeygenIntegrationTests.swift          # ✅ Existing (PEM/PKCS8 encryption)
├── CertificateSSHKeygenIntegrationTests.swift # ✅ Existing (Certificate verification)
├── OpenSSHFormatIntegrationTests.swift       # ✅ IMPLEMENTED (OpenSSH format bidirectional)
├── FingerprintIntegrationTests.swift         # ✅ IMPLEMENTED (All fingerprint algorithms)
├── RFC4716IntegrationTests.swift             # ✅ IMPLEMENTED (RFC4716 format)
├── PassphraseIntegrationTests.swift          # ✅ IMPLEMENTED (Passphrase operations)
├── RandomartIntegrationTests.swift           # ✅ IMPLEMENTED (Randomart and bubble babble)
├── ParseSSHKeygenKeysIntegrationTests.swift  # ✅ NEW - Parse ssh-keygen generated keys
├── ParseSSHKeygenCertificatesIntegrationTests.swift # ✅ NEW - Parse ssh-keygen certificates
├── SignatureVerificationIntegrationTests.swift # ✅ NEW - Signature verification bidirectional
├── CertificateAdvancedIntegrationTests.swift # ✅ NEW - Advanced certificate features & host certs
└── KnownHostsIntegrationTests.swift          # 🆕 known_hosts file handling (TODO - lower priority)
```

## 🎯 Immediate Next Steps

✅ **ALL HIGH PRIORITY TESTS COMPLETED!**

Successfully implemented 4 new comprehensive test suites:

1. ✅ **ParseSSHKeygenKeysIntegrationTests.swift** - Parse keys generated by ssh-keygen
2. ✅ **ParseSSHKeygenCertificatesIntegrationTests.swift** - Parse certificates created by ssh-keygen
3. ✅ **SignatureVerificationIntegrationTests.swift** - Bidirectional signature verification
4. ✅ **CertificateAdvancedIntegrationTests.swift** - Host certificates, options, extensions, edge cases

**Coverage Summary:**
- ✅ Parse all ssh-keygen key types (Ed25519, RSA, ECDSA) with and without passphrases
- ✅ Parse all ssh-keygen certificate types (user, host) with all CA types
- ✅ Verify ssh-keygen signatures (all algorithms: Ed25519, RSA SHA-256/512, ECDSA P-256/384/521)
- ✅ ssh-keygen verifies our signatures (bidirectional verification)
- ✅ Host certificates with all CA types
- ✅ Certificate critical options (force-command, source-address)
- ✅ Certificate extensions handling
- ✅ Certificate validity checks
- ✅ Multiple principals and wildcard support
- ✅ Comment preservation from ssh-keygen keys

**Lower Priority Remaining:**
- KnownHostsIntegrationTests.swift (known_hosts file handling)
- Large RSA key sizes (8192, 16384 bits)
- Certificate validity edge cases (expired, not-yet-valid)
- Format conversion round-trips
- Error handling parity

## 📝 Notes

- All tests should use `IntegrationTestSupporter` for consistency
- Tag tests appropriately: `.integration`, `.slow` (for crypto-heavy tests like RSA)
- Include both directions: "we read theirs" and "they read ours"
- Test with actual `ssh-keygen` binary (skip gracefully if not available)
- Compare outputs byte-for-byte when possible, semantically when necessary
- Document any intentional deviations from ssh-keygen behavior
