# SwiftKeyGen Feature Comparison with ssh-keygen

This document compares the features implemented in SwiftKeyGen with the original ssh-keygen tool.

## ✅ Implemented Features

### Key Generation
- [x] Generate Ed25519 keys (recommended, fixed size)
- [x] Generate RSA keys (2048, 3072, 4096 bits) - Note: ssh-keygen defaults to 3072
- [x] Generate ECDSA keys (256, 384, 521 bits)
- [x] Specify custom bit sizes for RSA keys
- [x] Generate multiple keys in batch mode
- [x] Set custom filenames and paths for keys
- [x] Add comments to keys during generation

### Key Management
- [x] Add passphrases to keys
- [x] Change passphrases on existing keys
- [x] Remove passphrases from existing keys
- [x] Update key comments
- [x] Show key fingerprints in multiple formats (MD5, SHA256, SHA512)
- [x] Display key fingerprints as randomart images
- [x] Print public key from private key
- [x] Read encrypted OpenSSH private keys
- [x] Verify passphrases without decrypting keys
- [x] Get key information without decryption

### Key Conversion
- [x] Convert between OpenSSH and PEM formats
- [x] Export keys to PKCS#8 format
- [x] Read and validate key formats
- [x] Parse OpenSSH private key format

### Host Key Management
- [x] Update known_hosts files
- [x] Remove host keys from known_hosts
- [x] Hash hostnames in known_hosts (must use HMAC-SHA1 with |1|salt|hash format)
- [x] Find hosts in known_hosts
- [x] Check host keys against known_hosts

### Security Features
- [x] Use AES encryption for private keys
- [x] Custom KDF rounds for key encryption
- [x] Secure file permissions (0600 for private keys)
- [x] Memory safety through Swift's ARC

### Advanced Options
- [x] Batch mode operation
- [x] Key validation and format checking
- [x] Compare key fingerprints
- [x] Extract public key components

### Format Support
- [x] OpenSSH private key format (default)
- [x] OpenSSH public key format
- [x] PEM format
- [x] PKCS#8 format (basic)

### Output Options
- [x] Fingerprint output in hex (MD5) or base64 (SHA256/512)
- [x] Visual randomart representation
- [x] Custom output file specifications

### Certificate Operations
- [x] Sign user certificates with CA keys
- [x] Sign host certificates with CA keys
- [x] Create certificate authority (CA) keys
- [x] Specify certificate validity periods
- [x] Add principals to certificates
- [x] Add critical options to certificates
- [x] Add extensions to certificates
- [x] Verify certificate signatures (including RSA and ECDSA)
- [x] Show certificate details
- [x] RSA signature verification (ssh-rsa, rsa-sha2-256, rsa-sha2-512)
- [x] ECDSA signature verification (P-256, P-384, P-521)
- [x] Public-key-only verification for certificates

## ❌ Not Implemented

### Key Generation
- [ ] Generate DSA keys (legacy, 1024 bits)
- [ ] Generate XMSS keys

### Key Conversion
- [x] Import keys from other SSH implementations (RFC4716 format)
- [ ] Convert SSH1 keys to SSH2 format (legacy, not implemented)
- [x] Read keys from standard input
- [x] Output keys to standard output

### Security Features
- [ ] Use hardware security tokens (PKCS#11)
- [ ] Generate FIDO/U2F security keys
- [ ] Specify resident keys for FIDO devices
- [ ] Set PIN requirements for security keys

### Advanced Options
- [ ] Moduli generation and testing for DH groups
- [ ] Screen DH group exchange moduli
- [ ] Generate keys deterministically from seed
- [ ] Memory locking to prevent key swapping

### Format Support
- [x] RFC4716 format
- [ ] SSH1 format (legacy)

### Output Options
- [ ] Bubble babble format for fingerprints

### Compatibility Features
- [ ] SSH1 protocol support (deprecated)
- [ ] Legacy key type support (DSA)

### Integration Features
- [ ] SSH agent integration
- [ ] Hardware security module support
- [ ] Certificate authority integration

## Implementation Notes

### Key Differences from ssh-keygen

1. **Pure Swift Implementation**: SwiftKeyGen is written entirely in Swift.

2. **Modern Cryptography**: Uses Apple's CryptoKit and swift-crypto libraries instead of OpenSSL.

3. **Type Safety**: Leverages Swift's type system to prevent common errors.

4. **Async/Await Support**: Batch operations support Swift's modern concurrency model.

5. **Simplified KDF**: Uses PBKDF2 with SHA512 instead of bcrypt_pbkdf for key derivation (WARNING: This means encrypted private keys from ssh-keygen may not be importable).

### Limitations

1. **No DSA Support**: DSA is considered legacy and not recommended for new deployments.

2. **No PKCS#11**: Hardware token support would require additional dependencies.

3. **Private Key Import**: SwiftKeyGen now supports importing RSA and ECDSA private keys from PEM/PKCS#8 formats using Swift Crypto's built-in `init(pemRepresentation:)` methods. Ed25519 keys are not supported for PEM import as Swift Crypto's Curve25519 implementation doesn't include PEM parsing. For Ed25519, users must use the OpenSSH format.

4. **Simplified Encryption**: Uses a simplified AES-CTR implementation; may not be fully compatible with all OpenSSH encrypted keys.

## Future Development

Priority features for future implementation:
1. ~~Full OpenSSH private key format compatibility (reading encrypted keys)~~ ✅ Completed
2. ~~SSH certificate support~~ ✅ Completed
3. KRL (Key Revocation List) support for certificate revocation
4. Improved key format conversion (RSA/ECDSA certificate support)
5. Hardware security key support