# Copilot Instructions for SwiftKeyGen

Purpose: Enable AI coding agents to work productively in this repository with minimal ramp‑up. Keep responses precise, follow existing patterns, and prefer real examples from this codebase.

## Project Overview

### Technology Stack
- **Language/Tooling**: Swift 6.2 Package (SPM)
- **Test Framework**: Swift Testing (not XCTest)
- **Primary Targets**: 
  - Library: `SwiftKeyGen`
  - CLI Tools: `swiftkeygen`, `HMACVerifyTool`
- **External Dependencies**: `swift-crypto`, `BigInt`

### Core Domains
- SSH key generation, parsing, conversion, fingerprinting
- SSH certificates (signing, verification, management)
- Cryptography primitives (AES, ChaCha, HMAC, BCrypt, KDF)
- Format support: OpenSSH, PEM, PKCS, ASN.1, DER

### Key Directory Map
- `Sources/SwiftKeyGen/Core/`: High-level APIs (`KeyGeneration`, `KeyManager`, `KeyPair`, `KeyType`, `SSHKeyError`).
- `Sources/SwiftKeyGen/Keys/`: Concrete key types and public key models (`RSAKey`, `Ed25519Key`, `ECDSAKey`, `PublicKeys`); protocols live in `Keys/Protocols/` (`SSHKey`, `SSHPublicKey`).
- `Sources/SwiftKeyGen/Formats/`: Format parsing and encoding. Subfolders: `OpenSSH/`, `RFC4716/`, `PEM/`, `PKCS/`, `DER/`, `ASN1/`, `SSH/`, `Common/`.
- `Sources/SwiftKeyGen/SSH/`: SSH-specific helpers and data (e.g., `KnownHosts/`).
- `Sources/SwiftKeyGen/Utilities/`: Helpers and tooling:
  - `IO/` (file I/O, e.g., `KeyFileManager`)
  - `Fingerprints/` (random art, bubble babble)
  - `Batch/` (batch key generation)
  - `Encoding/` (e.g., `ECDSAEncoding`)
- `Sources/SwiftKeyGen/Certificates/`: SSH certificate signing, parsing, verification, and models (`Models/SSHCertificate.swift`).
- `Sources/SwiftKeyGen/Cryptography/`: Cipher + KDF + primitives:
  - `Ciphers/` (AES, ChaCha20-Poly1305, 3DES)
  - `KDF/` (`BCrypt`)
  - `Primitives/` (`Blowfish`, RSA helpers)
- `Sources/SwiftKeyGen/Conversion/`: Format conversion orchestration (`KeyConversionManager`, `KeyConversion`).
- **`Sources/SwiftKeyGen/Extensions/`**: **Reusable extensions on standard types**. **ALWAYS check here first** to avoid duplicating helpers. Add new cross-cutting extensions here for project-wide reuse.
- `Sources/SwiftKeyGenCLI/`: Main CLI logic (argument parsing, stdout formatting).
- `Sources/HMACVerifyTool/`: Auxiliary CLI for HMAC verification.
- `Sources/CCommonCryptoShims/`: C shims for CommonCrypto (internal bridging headers).
- `Tests/SwiftKeyGenTests/`: Organized by domain (e.g., `Keys/`, `Cryptography/`, `FormatConversion/`, `Integration/`, `Utilities/`, `Certificates/`).

## Build and Test Commands

### Building
```bash
swift build
```

### Testing

> **Important**: Do NOT run the full test suite with `swift test` in this repository. Many tests exercise cryptography‑heavy paths (large key generation, KDFs, ciphers, integration flows) and can take a long time. Prefer targeted runs using filters or tags.

```bash
# Recommended: run a specific test or subset by name/regex
swift test --filter <TestNameOrRegex>

# Not recommended here — full suite is slow and unnecessary
# swift test
```

### Running CLI
```bash
# Main CLI tool
swift run swiftkeygen <command> [options]

# HMAC verification tool
swift run HMACVerifyTool
```

### Xcode Project
```bash
# Generate only if explicitly needed
swift package generate-xcodeproj
```

## Code Style Guidelines

### Swift Naming Conventions
**CRITICAL**: All code MUST follow [Swift API Design Guidelines](https://swift.org/documentation/api-design-guidelines/). Key rules:

- **Types**: `UpperCamelCase` (e.g., `KeyManager`, `RSAKey`, `CertificateAuthority`)
- **Functions/Methods/Properties**: `lowerCamelCase` (e.g., `generateKeyPair()`, `publicKeyString`, `isValid`)
- **Enums/Cases**: Type is `UpperCamelCase`, cases are `lowerCamelCase` (e.g., `KeyType.ed25519`, `SSHKeyError.invalidFormat`)
- **Acronyms**: Treat as words—uppercase when type name (e.g., `RSAKey`, `SSHCertificate`), lowercase in compound names (e.g., `rsaKeySize`, `sshPublicKey`)
- **Boolean Properties**: Use `is`/`has` prefix (e.g., `isEmpty`, `isValid`, `hasPassphrase`)
- **Factory Methods**: Start with `make`/`generate`/`create` verb (e.g., `generateKeyPair()`, `makeFingerprint()`)
- **Conversions**: Use `to<Type>()` or `as<Type>()` pattern (e.g., `toPEM()`, `asOpenSSHString()`)
- **Parameters**: Omit first label when method reads naturally (e.g., `parse(_: Data)` not `parse(data: Data)`); use labels for clarity after first param
- **Avoid**: snake_case, Hungarian notation, unnecessary abbreviations

**When reviewing existing code**: If you spot violations, fix them. When adding new code, get it right the first time.

### Design & Patterns
- **Public API**: Funnel through static factories (e.g. `SwiftKeyGen.generateKeyPair`, `KeyFileManager.generateKeyPairFiles`). Mimic this style for new capabilities.
- **Key Types**: Expose generation, signing, verification, public serialization (OpenSSH string), fingerprinting.
- **Parsing**: Return structured tuples or dedicated model types; preserve metadata (comments, key IDs, principals).
- **Certificate Operations**: Respect separation—`CertificateAuthority` (sign), `CertificateManager` (CRUD + convenience), `CertificateVerifier` (validation).
- **Type Safety**: Use strongly typed enums for key types, formats, hash/fingerprint algorithms; avoid raw strings.
- **Immutability**: Prefer immutable structs/value types; mutation only when required (e.g. passphrase changes) via dedicated manager methods.
- **Extensions First**: Before implementing utility methods on types, **check `Sources/SwiftKeyGen/Extensions/` first**. If the helper doesn't exist, add it there for project-wide reuse rather than scattering utilities across domain-specific files.

### Error Handling
- **Central Error Enum**: `SSHKeyError` (extend with case + doc comment if adding). Reuse existing cases before creating new ones.
- **Input Validation**: Validate early (e.g. key size ranges, format magic bytes) to mirror existing defensive style in parsers.

### Cryptography Guidelines
- **Primitives**: Delegate to `swift-crypto` / existing implementations; do NOT introduce new third-party crypto libs.
- **Randomness**: Do not roll custom randomness; use existing secure generators already abstracted in utilities.
- **Algorithm Naming**: Maintain consistency with OpenSSH (`ssh-ed25519`, `rsa-sha2-256`, etc.).

### Performance Considerations
- **Memory**: Avoid unnecessary key material copies; pass `Data` by reference where possible.
- **Big Numbers**: For large RSA support, rely on existing `BigInt` usage. Do not reinvent big number math.
- **Value Containers**: Prefer Swift 6.2 value containers (`InlineArray`, `Span`) over heap-backed `[T]` or raw pointer slices when size is static or when only a view is needed. This reduces allocations and improves cache locality while keeping memory safety.

#### InlineArray & Span Usage (Swift 6.2)
Swift 6.2 adds `InlineArray` (fixed-size, inline storage) and `Span` (a safe, non-owning view over contiguous memory) which we adopt for low-level, performance‑critical code.

Refer to `Docs/InlineArray`, `Docs/Span`, and `Docs/Data.md` for full guidance.

### CLI Extensions
- CLI logic lives in `Sources/SwiftKeyGenCLI/`. Keep library free of CLI-only concerns (argument parsing, stdout formatting).
- Reuse library APIs; do not duplicate logic in CLI.

## Testing Instructions

### Test Organization
- Place tests in the nearest domain folder (`Tests/SwiftKeyGenTests/<Domain>`), mirroring corresponding source file locations.
- Use test file naming: `<SourceFileName><Unit|Integration>Tests.swift` (e.g., `RSAKeyUnitTests.swift`, `PEMParserIntegrationTests.swift`).
- Use existing tests as structural references—focused, data-driven, explicit assertions (e.g., `CertificateVerifierUnitTests.swift`, `AESGCMIntegrationTests.swift`).
- **Single Test Target**: Keep all tests in one target (`SwiftKeyGenTests`); use tags to organize by type rather than creating separate targets.

### Test Tags (Swift Testing)
Tags allow categorization and selective execution of tests without separate test targets. Define custom tags by extending `Tag`:

```swift
import Testing

extension Tag {
    @Tag static var unit: Self
    @Tag static var integration: Self
    @Tag static var performance: Self
    @Tag static var critical: Self
}
```

**Apply tags to tests:**
```swift
// Single tag
@Test(.tags(.unit))
func testKeyGeneration() { ... }

// Multiple tags
@Test(.tags(.integration, .critical))
func testEndToEndKeyFlow() { ... }
```

**Apply tags to entire suites:**
```swift
@Suite(.tags(.integration))
struct CertificateIntegrationTests {
    @Test func testCertificateSigning() { ... }
    @Test func testCertificateVerification() { ... }
}
```

**Run tests by tag:**
- **In Xcode**: Test navigator auto-groups by tags; select a tag to run those tests
- **Command line with xcodebuild** (requires Xcode 16.3+):
  ```bash
  # Run only tests with unit tag
  xcodebuild test -scheme SwiftKeyGen -only-testing-tags unit
  
  # Run all except integration tests
  xcodebuild test -scheme SwiftKeyGen -skip-testing-tags integration
  
  # Combine multiple tags
  xcodebuild test -scheme SwiftKeyGen -skip-testing-tags integration,performance
  ```
- **SPM (swift test)**: Tag filtering is **not yet supported** in SPM command-line tools (tracked as [swift-testing #591](https://github.com/swiftlang/swift-testing/issues/591)). Current workaround: use `--filter` with regex patterns matching test names

> Local guidance: Because this is a cryptography‑focused project, avoid running `swift test` without filters. Use `swift test --filter <TestNameOrRegex>` to run only the relevant unit/integration tests. In Xcode, prefer running by tag (e.g., only `.unit` or `.critical`).

**Recommended tags for this project:**
- `.unit` — Fast, focused tests of individual functions/types
- `.integration` — Multi-component tests (e.g., format conversion round-trips, CLI workflows)
- `.performance` — Benchmarks, large key generation
- `.critical` — Core security/correctness tests (run in CI always)

### Test Requirements
- Add at least one cross-format round‑trip test when adding a new format or conversion path.
- Test edge cases: parse failures (bad headers), boundary conditions, error paths.
- Integration tests via CLI if applicable.
- Tag tests appropriately to enable selective execution during development vs. CI.

### Adding Formats / Conversions
1. Implement low-level parse/serialize in `Formats/<FormatName>/`.
2. Integrate into `KeyConversionManager` detection & dispatch.
3. Add tests: detection, parse failures (bad headers), round‑trip, integration via CLI if applicable.
4. Update README only if user-facing.

### Certificate Testing
- Maintain ssh-keygen behavioral parity (validity defaults, principal handling, extension names).
- When modifying verification logic, update both `CertificateVerifier` and any helpers in `CertificateManager` plus associated tests (`Certificates/`).
