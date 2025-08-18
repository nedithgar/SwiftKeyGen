# Copilot Instructions for SwiftKeyGen

Purpose: Enable AI coding agents to work productively in this repository with minimal ramp‑up. Keep responses precise, follow existing patterns, and prefer real examples from this codebase.

## Quick Project Facts
- Language/Tooling: Swift 6.2 Package (SPM). Test framework: Swift Testing (not XCTest).
- Primary library target: `SwiftKeyGen` (+ CLI targets: `swiftkeygen`, `HMACVerifyTool`).
- Domains: SSH key generation, parsing, conversion, fingerprinting, certificates, cryptography primitives.
- External deps (Package.swift): `swift-crypto`, `BigInt`.

## Build & Run
- Build: `swift build`
- Run all tests: `swift test`
- Run CLI: `swift run swiftkeygen <command> [options]`
- HMAC tool: `swift run HMACVerifyTool`
- Generate Xcode project (only if explicitly needed): `swift package generate-xcodeproj`

## Key Directory Map (Core Surfaces)
- `Sources/SwiftKeyGen/Core/`: High-level APIs (`KeyGeneration`, `KeyManager`, `KeyPair`, error types).
- `Sources/SwiftKeyGen/Keys/`: Concrete key type models (`RSAKey`, `Ed25519Key`, `ECDSAKey`, `SSHKey`).
- `Sources/SwiftKeyGen/Formats/`: Format parsing & encoding (OpenSSH, PEM, PKCS, ASN.1, DER).
- `Sources/SwiftKeyGen/Utilities/`: Helpers (random art, bubble babble, batch gen, file IO, parsing).
- `Sources/SwiftKeyGen/Certificates/`: SSH certificate signing, parsing, verification.
- `Sources/SwiftKeyGen/Cryptography/`: Cipher + KDF + BCrypt + AES/ChaCha/HMAC primitives.
- `Sources/SwiftKeyGen/Conversion/`: Format conversion orchestration (`KeyConversionManager`).
- `Tests/SwiftKeyGenTests/`: Organized by domain; use as source of truth for expected behaviors.

## Design & Patterns
- Public API is largely funneled through static factories (e.g. `SwiftKeyGen.generateKeyPair`, `KeyFileManager.generateKeyPairFiles`). Mimic this style for new capabilities.
- Key types expose: generation, signing, verification, public serialization (OpenSSH string), fingerprinting.
- Parsing functions return structured tuples or dedicated model types; do not throw away metadata (e.g. comments, key IDs, principals).
- Certificate operations: `CertificateAuthority` (sign), `CertificateManager` (CRUD + convenience), `CertificateVerifier` (validation). Respect separation.
- Use strongly typed enums for key types, formats, hash/fingerprint algorithms; avoid raw strings.
- Prefer immutable structs/value types for parsed representations; mutation only when required (e.g. passphrase changes) via dedicated manager methods.

## Error Handling
- Central error enum: `SSHKeyError` (extend with case + doc comment if adding). Reuse existing cases before creating new ones.
- Validate inputs early (e.g. key size ranges, format magic bytes) to mirror existing defensive style in parsers.

## Cryptography Guidelines
- Delegate crypto primitives to `swift-crypto` / existing implementations; do NOT introduce new third-party crypto libs.
- Do not roll custom randomness; use existing secure generators already abstracted in utilities.
- Maintain algorithm naming consistent with OpenSSH (`ssh-ed25519`, `rsa-sha2-256`, etc.).

## Testing Conventions
- Put tests in the nearest domain folder (`Tests/SwiftKeyGenTests/<Domain>`).
- Follow existing naming: `<Feature>Tests.swift` or `<Format>ParserTests.swift`.
- Use current test examples (e.g. `RSABitSizeTest`, `PEMParserTests`) for structure—focused, data-driven, explicit assertions.
- Add at least one cross-format round‑trip test when adding a new format or conversion path.

## Adding Formats / Conversions
1. Implement low-level parse/serialize in `Formats/<FormatName>/`.
2. Integrate into `KeyConversionManager` detection & dispatch.
3. Add tests: detection, parse failures (bad headers), round‑trip, integration via CLI if applicable.
4. Update README only if user-facing.

## CLI Extensions
- CLI logic lives in `Sources/SwiftKeyGenCLI/`. Keep library free of CLI-only concerns (argument parsing, stdout formatting).
- Reuse library APIs; do not duplicate logic in CLI.

## Certificates
- Maintain ssh-keygen behavioral parity (validity defaults, principal handling, extension names).
- When modifying verification logic, update both `CertificateVerifier` and any helpers in `CertificateManager` plus associated tests (`Certificates/`).

## Performance Considerations
- Avoid unnecessary key material copies; pass `Data` by reference where possible.
- For large RSA support, rely on existing `BigInt` usage. Do not reinvent big number math.
- Prefer Swift 6.2 value containers (`InlineArray`, `Span`) over heap-backed `[T]` or raw pointer slices when size is static or when only a view is needed. This reduces allocations and improves cache locality while keeping memory safety.

### InlineArray & Span Usage (Swift 6.2)
Swift 6.2 adds `InlineArray` (fixed-size, inline storage) and `Span` (a safe, non-owning view over contiguous memory) which we adopt for low-level, performance‑critical code. Follow these rules:

- Use `InlineArray<Element, N>` for small, fixed-capacity working buffers (e.g. block cipher state, digest partial blocks, temporary key schedule scratch). This avoids dynamic heap allocation present in standard `Array`.
- Use `Span<Element>` (or a mutable variant when mutation is required) for read/write windows into existing storage instead of `Unsafe[Mutable]BufferPointer` or pointer + length pairs.
- Only fall back to regular `[T]` when length is genuinely dynamic or needs CoW semantics externally.
- Do not retain `Span` past the lifetime of its backing storage; design APIs so the span is consumed synchronously. (The type’s compile‑time guarantees already prevent dangling use—keep APIs simple so those guarantees remain obvious.)
- Prefer conversion patterns: existing `Array`/`Data` → create a `Span` view for algorithm steps; avoid copying into temporary buffers unless mutation + CoW avoidance demands `InlineArray`.
- Keep fixed sizes in a single source of truth (e.g. a `static let blockSize = 16`) and reference via generic parameter `N` when constructing an `InlineArray` to prevent mismatches.
- When interoperating with C APIs that require raw pointers, confine `withUnsafeBytes` / `withUnsafeMutableBytes` to the narrowest scope and immediately wrap the memory in a `Span` for internal processing.

Reference docs: see `Docs/InlineArray` and `Docs/Span` for the generated symbol documentation of initializers, indexing, and slicing helpers.

Rationale: These abstractions give predictable performance (no surprise allocations), eliminate classes of pointer lifetime bugs (use‑after‑free, double free), and keep code closer to pure Swift value semantics.

## Security Practices
- File writes must enforce permissions (0600 private, 0644 public) via `KeyFileManager`—reuse its methods instead of raw FileManager.
- Passphrase changes go through `KeyManager` (ensures re-encryption with correct KDF/hint metadata).

## When Unsure
- Look for a parallel implementation (e.g. add ECDSA change? Check existing RSA or Ed25519 pattern).
- Search tests first to confirm expected semantics before altering core logic.

## Non-Goals
- Do NOT introduce experimental crypto or unsupported key types without roadmap alignment.
- Avoid adding platform-specific code unless guarded with availability checks matching existing style.

## Example: Adding a New Fingerprint Format (Hypothetical)
- Extend enum (e.g. `FingerprintHash` or formatter enum) with case + documentation.
- Implement calculation using existing digest pipeline.
- Add display formatting in the same file as similar cases.
- Write tests: one known vector + integration through `KeyPair.fingerprint()`.

Keep changes small, incremental, and covered by tests. Provide concrete reasoning in PR descriptions (what OpenSSH behavior or spec you're matching).