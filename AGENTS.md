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
- `Sources/SwiftKeyGen/Core/`: High-level APIs (`KeyGeneration`, `KeyManager`, `KeyPair`, error types)
- `Sources/SwiftKeyGen/Keys/`: Concrete key type models (`RSAKey`, `Ed25519Key`, `ECDSAKey`, `SSHKey`)
- `Sources/SwiftKeyGen/Formats/`: Format parsing & encoding (OpenSSH, PEM, PKCS, ASN.1, DER)
- `Sources/SwiftKeyGen/Utilities/`: Helpers (random art, bubble babble, batch gen, file IO, parsing)
- `Sources/SwiftKeyGen/Certificates/`: SSH certificate signing, parsing, verification
- `Sources/SwiftKeyGen/Cryptography/`: Cipher + KDF + BCrypt + AES/ChaCha/HMAC primitives
- `Sources/SwiftKeyGen/Conversion/`: Format conversion orchestration (`KeyConversionManager`)
- `Sources/SwiftKeyGenCLI/`: CLI logic (keep library free of CLI-only concerns)
- `Tests/SwiftKeyGenTests/`: Organized by domain; use as source of truth for expected behaviors

## Build and Test Commands

### Building
```bash
swift build
```

### Testing
```bash
# Run all tests
swift test

# Run specific test file
swift test --filter <TestName>
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

### Design & Patterns
- **Public API**: Funnel through static factories (e.g. `SwiftKeyGen.generateKeyPair`, `KeyFileManager.generateKeyPairFiles`). Mimic this style for new capabilities.
- **Key Types**: Expose generation, signing, verification, public serialization (OpenSSH string), fingerprinting.
- **Parsing**: Return structured tuples or dedicated model types; preserve metadata (comments, key IDs, principals).
- **Certificate Operations**: Respect separation—`CertificateAuthority` (sign), `CertificateManager` (CRUD + convenience), `CertificateVerifier` (validation).
- **Type Safety**: Use strongly typed enums for key types, formats, hash/fingerprint algorithms; avoid raw strings.
- **Immutability**: Prefer immutable structs/value types; mutation only when required (e.g. passphrase changes) via dedicated manager methods.

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
Swift 6.2 adds `InlineArray` (fixed-size, inline storage) and `Span` (a safe, non-owning view over contiguous memory) which we adopt for low-level, performance‑critical code. Follow these rules:

- Use `InlineArray<Element, N>` for small, fixed-capacity working buffers (e.g. block cipher state, digest partial blocks, temporary key schedule scratch). This avoids dynamic heap allocation present in standard `Array`.
- Use `Span<Element>` (or a mutable variant when mutation is required) for read/write windows into existing storage instead of `Unsafe[Mutable]BufferPointer` or pointer + length pairs.
- Only fall back to regular `[T]` when length is genuinely dynamic or needs CoW semantics externally.
- Do not retain `Span` past the lifetime of its backing storage; design APIs so the span is consumed synchronously. (The type's compile‑time guarantees already prevent dangling use—keep APIs simple so those guarantees remain obvious.)
- Prefer conversion patterns: existing `Array`/`Data` → create a `Span` view for algorithm steps; avoid copying into temporary buffers unless mutation + CoW avoidance demands `InlineArray`.
- Keep fixed sizes in a single source of truth (e.g. a `static let blockSize = 16`) and reference via generic parameter `N` when constructing an `InlineArray` to prevent mismatches.
- When interoperating with C APIs that require raw pointers, confine `withUnsafeBytes` / `withUnsafeMutableBytes` to the narrowest scope and immediately wrap the memory in a `Span` for internal processing.

**Reference docs**: see `Docs/InlineArray`, `Docs/Span`, and `Docs/Data.md` (standard `Data` bridging + span helpers) for the generated symbol documentation of initializers, indexing, and slicing helpers.

**Rationale**: These abstractions give predictable performance (no surprise allocations), eliminate classes of pointer lifetime bugs (use‑after‑free, double free), and keep code closer to pure Swift value semantics.

### CLI Extensions
- CLI logic lives in `Sources/SwiftKeyGenCLI/`. Keep library free of CLI-only concerns (argument parsing, stdout formatting).
- Reuse library APIs; do not duplicate logic in CLI.

## Testing Instructions

### Test Organization
- Put tests in the nearest domain folder (`Tests/SwiftKeyGenTests/<Domain>`).
- Follow existing naming: `<Feature>Tests.swift` or `<Format>ParserTests.swift`.
- Use current test examples (e.g. `RSABitSizeTest`, `PEMParserTests`) for structure—focused, data-driven, explicit assertions.
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