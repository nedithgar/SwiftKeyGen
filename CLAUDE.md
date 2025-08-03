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

### Generate Xcode Project (if needed)
```bash
swift package generate-xcodeproj
```

## Project Architecture

SwiftKeyGen is a Swift library for cryptographic key generation. The project follows standard Swift Package Manager conventions:

- **Sources/SwiftKeyGen/**: Main library implementation
- **Tests/SwiftKeyGenTests/**: Test suite using Swift Testing framework (not XCTest)
- **Package.swift**: Package configuration with Swift tools version 6.1

## Key Development Notes

1. The project uses the modern Swift Testing framework instead of XCTest
2. No external dependencies are currently declared - add crypto dependencies to Package.swift when implementing key generation
3. The library target is named "SwiftKeyGen" - maintain this naming convention for new files
4. Follow Swift API Design Guidelines for public interfaces

## Key Conversion Features

SwiftKeyGen supports key format conversion matching ssh-keygen behavior:

- **RFC4716 format**: Import/export SSH2 public keys
- **PEM format**: Import RSA public keys in PKCS#1 format
- **PKCS#8 format**: Import public keys in SubjectPublicKeyInfo format
- **stdin/stdout support**: Use "-" as filename for piping
- **Format detection**: Automatically detect key format
- **Batch conversion**: Convert multiple keys at once

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