# Agent Instructions for SwiftKeyGen

Purpose: Enable AI coding agents to work productively in this repository with minimal ramp‑up. Keep responses precise, follow existing patterns, and prefer real examples from this codebase.

**IMPORTANT: Avoid using batch-editing tools (e.g. shell scripts, sed, awk, or mass-replacement commands). These operations are unsafe and may overwrite multiple files or entries unintentionally.**

## When you need to call tools from the shell, use this rubric:
- Find Files: `fd`
- Find Text: `rg` (ripgrep)
- Find Code Structure: `ast-grep`
  - Default to Swift:
    - `.swift` files: `ast-grep --lang swift -p '<pattern>'` (Swift is supported via tree-sitter); prefer precise code patterns over broad regex.
  - Other languages: adjust corresponding `--lang` for `ast-grep`.
- Select among matches: pipe to `fzf`
- JSON: `jq`
- YAML/XML: `yq`

## Project Overview

### Technology Stack
- **Language/Tooling**: Swift Package Manager package (`swift-tools-version: 6.2`, Swift language mode `.v6`)
- **Platform Baseline**: Apple platform v26 across macOS, iOS, tvOS, watchOS, Mac Catalyst, and visionOS (see `Package.swift`)
- **Test Framework**: Swift Testing (new framework, not XCTest)
- **Primary Targets**: 
  - Library: `SwiftKeyGen`
  - CLI Tool: `swiftkeygen`
- **External Dependencies**: `swift-crypto` (`Crypto`, `_CryptoExtras`) and `BigInt` (see [Package.swift](./Package.swift))

### Core Domains
- SSH key generation, parsing, conversion, fingerprinting
- SSH certificates (signing, verification, management)
- Cryptography primitives (AES-CBC/CTR/GCM, ChaCha20-Poly1305, 3DES, Blowfish, RSA helpers, HMAC/PBKDF2 use via `swift-crypto`, BCrypt KDF)
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
  - `Ciphers/AES/` (AES engine plus CBC, CTR, GCM)
  - `Ciphers/` (`ChaCha20Poly1305OpenSSH`, `TripleDESCBC`, cipher metadata)
  - `KDF/` (`BCrypt`)
  - `Primitives/` (`Blowfish/`, `RSA/InsecureRSA.swift`)
- `Sources/SwiftKeyGen/Conversion/`: Format conversion orchestration (`KeyConversionManager`, `KeyConversion`).
- **`Sources/SwiftKeyGen/Extensions/`**: **Reusable extensions on standard types**. **ALWAYS check here first** to avoid duplicating helpers. Add new cross-cutting extensions here for project-wide reuse.
- `Sources/SwiftKeyGen/SwiftKeyGen.docc/`: DocC documentation catalog.
- `Sources/SwiftKeyGenCLI/`: Main CLI logic (argument parsing, stdout formatting).
- `Tests/SwiftKeyGenTests/`: Organized by domain (e.g., `Keys/`, `Cryptography/`, `Formats/`, `Conversion/`, legacy `FormatConversion/`, `Integration/`, `Utilities/`, `Certificates/`, `Extensions/`).

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

# Useful when excluding a known-heavy regex
swift test --skip <TestNameOrRegex>

# Not recommended here — full suite is slow and unnecessary
# swift test
```

### Running CLI
```bash
# Main CLI tool
swift run swiftkeygen <command> [options]

# CLI commands currently implemented: generate, convert, export, version/help
# generate types: rsa, ed25519, ecdsa (ECDSA maps to P-256)
```

### Xcode
Open `Package.swift` directly in Xcode when needed. Do not rely on `swift package generate-xcodeproj`; modern SwiftPM no longer exposes that subcommand in the installed toolchain.

## Code Style Guidelines

### Swift Naming Conventions
**CRITICAL**: All code MUST follow [Swift API Design Guidelines](https://swift.org/documentation/api-design-guidelines/). Key rules:

- **Types**: `UpperCamelCase` (e.g., `KeyManager`, `RSAKey`, `CertificateAuthority`)
- **Functions/Methods/Properties**: `lowerCamelCase` (e.g., `generateKeyPair()`, `publicKeyString`, `isValid`)
- **Enums/Cases**: Enum types are `UpperCamelCase`, cases are `lowerCamelCase` (e.g., `SSHKeyError.invalidFormat`). Static constants on string-backed identifier structs also use `lowerCamelCase` (e.g., `KeyType.ed25519`, `KeyFormat.openssh`).
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
- **Type Safety**: Use domain types for key types, formats, hash/fingerprint algorithms; avoid passing raw strings through library APIs.
- **Extensible Identifiers**: `KeyType` and `KeyFormat` are string-backed structs rather than closed enums for forward compatibility. Preserve unknown raw values unless validation is explicitly required.
- **Immutability**: Prefer immutable structs/value types; mutation only when required (e.g. passphrase changes) via dedicated manager methods.
- **Extensions First**: Before implementing utility methods on types, **check `Sources/SwiftKeyGen/Extensions/` first**. If the helper doesn't exist, add it there for project-wide reuse rather than scattering utilities across domain-specific files.

### Error Handling
- **Central Error Enum**: `SSHKeyError` (extend with case + doc comment if adding). Reuse existing cases before creating new ones.
- **Input Validation**: Validate early (e.g. key size ranges, format magic bytes) to mirror existing defensive style in parsers.

### Cryptography Guidelines
- **Primitives**: Delegate to `swift-crypto` / existing implementations; do NOT introduce new third-party crypto libs.
- **Randomness**: Do not roll custom randomness; use existing secure generators already abstracted in utilities.
- **Known Legacy Crypto**: `Insecure.RSA`, `Insecure.SHA1`, and MD5 appear only for OpenSSH interoperability, fingerprints/randomart, or compatibility tests. Do not expand insecure usage for new security-sensitive behavior.
- **Algorithm Naming**: Maintain consistency with OpenSSH (`ssh-ed25519`, `rsa-sha2-256`, etc.).

### Performance Considerations
- **Memory**: Avoid unnecessary key material copies; pass references (`Data` is a value type with copy-on-write—leverage that). Zero sensitive buffers promptly if you introduce temporary storage (follow existing patterns before adding new wipes).
- **Big Numbers**: For large RSA support, rely on existing `BigInt` usage. Do not re‑implement big integer arithmetic.
- **Value Containers**: Prefer Swift 6.2 value containers (`InlineArray`, `Span`) over heap-backed `[T]` or raw pointer slices when capacity is fixed or when only a transient, read‑only view is needed. This reduces allocations and improves cache locality while keeping memory safety.
- **`InlineArray` vs `Data`**: Use `InlineArray<Fixed, UInt8>` for fixed cryptographic blocks (e.g., bcrypt blocks, digest buffers). Convert to `Data` only at API boundaries via existing extensions (`toData()`).
- **Hot Paths**: Favor tight loops without heap traffic; check existing cipher/KDF implementations for style before adding similar code.

#### InlineArray & Span Usage (Swift 6.2)
Swift 6.2 adds `InlineArray` (fixed-size, inline storage) and `Span` (a safe, non-owning view over contiguous memory) which we adopt for low-level, performance‑critical code. Utilize MCP servers to progressively retrieve additional details until sufficient information is obtained.

### CLI Extensions
- CLI logic lives in `Sources/SwiftKeyGenCLI/`. Keep library free of CLI-only concerns (argument parsing, stdout formatting).
- Reuse library APIs; do not duplicate logic in CLI.

### Documentation (DocC)
- Use DocC formatting for documentation.

## Testing Instructions

### Test Organization
- Place tests in the nearest domain folder (`Tests/SwiftKeyGenTests/<Domain>`), mirroring corresponding source file locations.
- Use test file naming: `<SourceFileName><Unit|Integration>Tests.swift` (e.g., `RSAKeyUnitTests.swift`, `PEMParserIntegrationTests.swift`).
- Use existing tests as structural references—focused, data-driven, explicit assertions (e.g., `CertificateVerifierUnitTests.swift`, `AESGCMIntegrationTests.swift`).
- **Single Test Target**: Keep all tests in one target (`SwiftKeyGenTests`); use tags to organize by type rather than creating separate targets.

### Test Tags (Swift Testing)
Tags allow categorization and selective execution of tests without separate test targets. Current tag definitions: [`Tests/SwiftKeyGenTests/Tags.swift`](Tests/SwiftKeyGenTests/Tags.swift)

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
- **In Xcode**: Test navigator auto‑groups by tags; select a tag to run those tests.
- **Command line**: Prefer SwiftPM filters for local work. Tag filtering is not available in SwiftPM command-line tools, and `xcodebuild` tag flags vary by installed Xcode version. Verify support with `xcodebuild -help` before relying on tag-specific flags.
  ```bash
  # Practical local equivalents using SwiftPM regex filters
  swift test --filter KeyGenerationUnitTests
  swift test --filter 'SwiftKeyGenTests\\.(KeyGenerationUnitTests|KeyTypeUnitTests)'
  swift test --skip 'Integration|RSA|BCrypt|Performance'
  ```
- **SPM (swift test)**: Tag filtering is **not yet supported** in SPM command-line tools (tracked as [swift-testing #591](https://github.com/swiftlang/swift-testing/issues/591)). Current workaround: use `--filter` with regex patterns matching test names

> Local guidance: Because this is a cryptography‑focused project, avoid running `swift test` without filters. Use `swift test --filter <TestNameOrRegex>` to run only the relevant unit/integration tests. In Xcode, prefer running by tag when the installed Xcode supports it (e.g., only `.unit`, `.critical`, or domain-specific tags like `.rsa`).

### Slow Policy

Policy: Always run any test or suite tagged `.slow` in Release mode first: `swift test -c release --filter <SuiteOrTestName>`; default Debug loops should exclude them.

### Test Requirements
- Add at least one cross-format round‑trip test when adding a new format or conversion path.
- Provide a negative test (malformed header / unsupported algorithm) alongside each new parser.
- Test edge cases: parse failures (bad headers), boundary conditions, error paths, minimal & maximal key sizes.
- Add CLI integration coverage if user-visible behavior changes.
- Tag tests appropriately to enable selective execution during development vs. CI.
- For new cryptographic primitives: include at least one known-answer test (KAT) vector when implementing from scratch. For wrappers around `swift-crypto` or validating interoperability with external tools (e.g., ssh-keygen, OpenSSL), property-based tests (determinism, round-trip, avalanche effect) are acceptable, though KAT vectors from authoritative sources (NIST, RFCs, reference implementations) are strongly recommended where available.

### Adding Formats / Conversions
1. Implement low-level parse/serialize in `Formats/<FormatName>/`.
2. Integrate into `KeyConversionManager` detection & dispatch.
3. Add tests: detection, parse failures (bad headers), round‑trip, integration via CLI if applicable.
4. Update README only if user-facing.

### Certificate Testing
- Maintain ssh-keygen behavioral parity.
- When modifying verification logic, update both `CertificateVerifier` and any helpers in `CertificateManager` plus associated tests (`Certificates/`).
