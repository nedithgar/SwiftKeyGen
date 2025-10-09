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
- [x] **ssh-keygen changes passphrase on our PEM key**
- [x] **ssh-keygen changes passphrase on our PKCS8 key**
	- [x] RSA key (encrypted PKCS#8) passphrase change (added via RSA PKCS#8 implementation)
- [x] **We change passphrase on ssh-keygen OpenSSH key** (if KeyManager supports)
- [x] **We remove passphrase from ssh-keygen key** (if KeyManager supports)
- [x] **Passphrase operation preserves key integrity**

### PKCS8 Decryption (Parser & Round-Trip)
- [x] **Decrypt our encrypted PKCS8 key (ECDSA AES-128-CBC)**
- [x] **Decrypt ssh-keygen encrypted PKCS8 key (ECDSA)**
- [x] **Decrypt ssh-keygen encrypted PKCS8 key (RSA 2048)**
- [ ] Decrypt PKCS8 with AES-256-CBC (when emission added)
- [ ] Decrypt PKCS8 with HMAC-SHA256 PRF (when emission added)
- [ ] Decrypt PKCS8 Ed25519 (after PKCS8 Ed25519 emission implementation)
- [ ] Validate decrypted PrivateKeyInfo → re-emit and compare ssh-keygen output (canonical DER)

### Bubble Babble Format
- [x] **Bubble babble matches ssh-keygen** (Ed25519)
- [x] **Bubble babble matches ssh-keygen** (RSA)
- [x] **Bubble babble matches ssh-keygen** (ECDSA all curves)
- [x] **Bubble babble format structure** (hyphen separation, vowel-consonant pattern)

## 🟢 LOWER PRIORITY - Completeness

### Known Hosts Interoperability
- [x] **Parse ssh-keygen known_hosts entries** (plain hostname)
- [x] **Parse ssh-keygen known_hosts entries** (hashed hostname)
- [x] **Parse ssh-keygen known_hosts entries** (IP addresses)
- [x] **Parse ssh-keygen known_hosts entries** (hostname patterns)
- [x] **ssh-keygen reads our known_hosts format**
- [x] **Hashed hostname compatibility** (HMAC-SHA1 format)
- [x] **known_hosts entry verification** (key matching)
- [x] **known_hosts hostname hashing bidirectional**
- [x] **known_hosts with comments and blank lines**
- [x] **ssh-keygen -R removes our entries**
- [x] **Round-trip: ssh-keygen → us → ssh-keygen**

### ~~Large and Edge-Case Key Sizes~~ (NOT PLANNED)
- [x] ~~**ssh-keygen reads our RSA 8192-bit key**~~
- [x] ~~**We read ssh-keygen RSA 16384-bit key**~~
- [x] ~~**ssh-keygen reads our arbitrary RSA key sizes** (1536, 2560, etc.)~~
- [x] ~~**Minimum key size handling** (1024-bit RSA)~~
- [x] ~~**Performance test for large keys** (generation and parsing)~~

### Certificate Advanced Features
- [x] **Certificate with force-command critical option**
- [x] **Certificate with source-address restriction** (IPv4)
- [x] **Certificate with source-address restriction** (IPv6)
- [x] **Certificate with source-address restriction** (CIDR notation)
- [x] **Certificate with verify-required option**
- [x] **Certificate with no-presence-required option**
- [x] **Certificate with custom extensions** (non-standard)
- [x] **Certificate extension permit-X11-forwarding**
- [x] **Certificate extension permit-agent-forwarding**
- [x] **Certificate extension permit-port-forwarding**
- [x] **Certificate extension permit-pty**
- [x] **Certificate extension permit-user-rc**
- [x] **Multiple principals handling**
- [x] **Empty principals list** (wildcard access)
- [x] **Certificate serial number handling** (large values)

### Certificate Validity Edge Cases
- [x] **Expired certificate handling** (past valid_before)
- [x] **Not-yet-valid certificate handling** (future valid_after)
- [x] **Certificate valid for exactly 1 second**
- [x] **Certificate with forever validity** (0xFFFFFFFFFFFFFFFF)
- [x] **Certificate validity boundary conditions**

### Format Edge Cases
- [x] **Keys with unusual comments** (Unicode, special characters)
- [x] **Keys with very long comments** (>255 characters)
- [x] **Keys with no comment**
- [x] **Public key with extra whitespace** (leading, trailing, multiple spaces)
- [x] **Public key with tabs instead of spaces**
- [x] **Public key wrapped across multiple lines** (RFC4716)
- [x] **Malformed key handling** (truncated base64, invalid type)
- [x] **Mixed line endings** (CRLF vs LF)

### Error Handling Parity
- [x] **Both reject keys with wrong passphrase** (same error behavior)
- [x] **Both reject malformed base64 encoding**
- [x] **Both reject invalid key type identifiers**
- [x] **Both reject certificates with invalid signatures**
- [x] **Both reject expired certificates** (same error message/code)
- [x] **Both handle corrupted key files** (similar recovery or failure)

### Format Conversion Round-Trips
- [x] **OpenSSH → PEM → OpenSSH** (via both tools)
- [x] **OpenSSH → PKCS8 → OpenSSH** (via both tools)
- [x] **PEM → PKCS8 → PEM** (via both tools)
- [x] **OpenSSH → RFC4716 → OpenSSH** (public key only)
- [x] **All conversions preserve public key integrity**

## 📁 Suggested Test File Organization

```
Tests/SwiftKeyGenTests/Integration/
├── CertificateAdvancedIntegrationTests.swift      # ✅ IMPLEMENTED - Advanced certificate features & host certs
├── CertificateSSHKeygenIntegrationTests.swift     # ✅ IMPLEMENTED - Certificate verification
├── CertificateValidityIntegrationTests.swift      # ✅ IMPLEMENTED - Certificate validity edge cases
├── ErrorHandlingParityIntegrationTests.swift      # ✅ IMPLEMENTED - Error handling parity with ssh-keygen
├── FingerprintIntegrationTests.swift              # ✅ IMPLEMENTED - All fingerprint algorithms
├── FormatConversionRoundTripIntegrationTests.swift # ✅ IMPLEMENTED - Format conversion round-trips
├── FormatEdgeCasesIntegrationTests.swift          # ✅ IMPLEMENTED - Format edge cases
├── KnownHostsIntegrationTests.swift               # ✅ IMPLEMENTED - known_hosts file handling
├── OpenSSHFormatIntegrationTests.swift            # ✅ IMPLEMENTED - OpenSSH format bidirectional
├── ParseSSHKeygenCertificatesIntegrationTests.swift # ✅ IMPLEMENTED - Parse ssh-keygen certificates
├── ParseSSHKeygenKeysIntegrationTests.swift       # ✅ IMPLEMENTED - Parse ssh-keygen generated keys
├── PassphraseIntegrationTests.swift               # ✅ IMPLEMENTED - Passphrase operations (OpenSSH, PEM, PKCS8)
├── PKCS8DecryptionIntegrationTests.swift          # ✅ IMPLEMENTED - PKCS8 parser + decryption (PBES2/AES-128-CBC)
├── RandomartIntegrationTests.swift                # ✅ IMPLEMENTED - Randomart and bubble babble
├── RFC4716IntegrationTests.swift                  # ✅ IMPLEMENTED - RFC4716 format
├── SignatureVerificationIntegrationTests.swift    # ✅ IMPLEMENTED - Signature verification bidirectional
└── SSHKeygenIntegrationTests.swift                # ✅ IMPLEMENTED - PEM/PKCS8 encryption
```

## 📝 Notes

- All tests should use `IntegrationTestSupporter` for consistency
- Tag tests appropriately: `.integration`, `.slow` (for crypto-heavy tests like RSA)
- Include both directions: "we read theirs" and "they read ours"
- Test with actual `ssh-keygen` binary (skip gracefully if not available)
- Compare outputs byte-for-byte when possible, semantically when necessary
- Document any intentional deviations from ssh-keygen behavior
