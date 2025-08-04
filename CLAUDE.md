# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build
```bash
swift build
```

### Run Tests
```bash
swift test
```

### Run CLI Tool
```bash
swift run swiftkeygen [command] [options]
```

### Run HMAC Verification Tool
```bash
swift run HMACVerifyTool
```

### Generate Xcode Project (if needed)
```bash
swift package generate-xcodeproj
```

## Project Architecture

SwiftKeyGen is a comprehensive Swift package for SSH key generation, management, and certificate operations. The project provides both a library and command-line tools:

### Products
- **SwiftKeyGen**: Main library for programmatic key operations
- **swiftkeygen**: Command-line tool matching ssh-keygen functionality
- **HMACVerifyTool**: Utility for HMAC verification testing

### Directory Structure
- **Sources/SwiftKeyGen/**: Core library implementation
  - **Certificates/**: SSH certificate creation, parsing, and verification
  - **Conversion/**: Key format conversion utilities
  - **Core/**: Key generation and management fundamentals
  - **Cryptography/**: Cipher implementations (AES, ChaCha20, BCrypt, etc.)
  - **Extensions/**: Additional cryptographic functionality
  - **Formats/**: Support for various key formats (ASN.1, DER, OpenSSH, PEM, PKCS)
  - **Keys/**: Key type implementations (RSA, ECDSA, Ed25519)
  - **SSH/**: SSH-specific functionality (known hosts, certificates)
  - **Utilities/**: Helper functions (BubbleBabble, RandomArt, batch operations)
- **Sources/SwiftKeyGenCLI/**: Command-line interface implementation
- **Sources/HMACVerifyTool/**: HMAC verification utility
- **Tests/SwiftKeyGenTests/**: Comprehensive test suite using Swift Testing framework
- **Examples/**: Usage examples for common scenarios

### Dependencies
- **swift-crypto** (3.0.0+): Core cryptographic operations
- **BigInt** (5.3.0+): Large number operations for RSA

## Key Development Notes

1. The project uses the modern Swift Testing framework instead of XCTest
2. Supports Swift 6.1 with platform requirements:
   - macOS 13+, iOS 16+, tvOS 16+, watchOS 9+, visionOS 1+
3. The library target is named "SwiftKeyGen" - maintain this naming convention
4. Follow Swift API Design Guidelines for public interfaces
5. Cryptographic operations leverage Apple's swift-crypto and _CryptoExtras

## Key Conversion Features

SwiftKeyGen supports key format conversion matching ssh-keygen behavior:

- **RFC4716 format**: Import/export SSH2 public keys
- **PEM format**: Import RSA public keys in PKCS#1 format
- **PKCS#8 format**: Import public keys in SubjectPublicKeyInfo format
- **stdin/stdout support**: Use "-" as filename for piping
- **Format detection**: Automatically detect key format
- **Batch conversion**: Convert multiple keys at once

## Certificate Defaults

SwiftKeyGen matches ssh-keygen's default behavior:
- **Default validity**: Forever (0 to max UInt64), matching ssh-keygen
- **Validity override**: Use -V option to specify custom validity period

Supported conversions:
- OpenSSH ↔ RFC4716
- PEM → OpenSSH
- PKCS#8 → OpenSSH
- Any format → RFC4716

Example usage:
```bash
# Convert OpenSSH to RFC4716
cat ~/.ssh/id_ed25519.pub | swift run swiftkeygen convert -f openssh -t rfc4716 -

# Convert PEM RSA to OpenSSH
swift run swiftkeygen convert -f pem -t openssh rsa_public.pem

# Export key to stdout
swift run swiftkeygen export - < key.pub
```