Debug-Only or Investigatory Tests Identified

These test files/functions appear to be used primarily for debugging or exploratory investigation rather than asserting behavior. They often rely on print output, contain no meaningful assertions, or include TODO placeholders. Consider removing, converting to proper assertions, or relocating to developer docs/examples.

- Tests/SwiftKeyGenTests/FormatConversion/CompareFormatTest.swift
  - Test: compareFormat
  - Reason: Exploratory dump of OpenSSH private key structure (hex dumps, offsets) using print statements; contains no assertions (#expect). Used for manual inspection rather than verification.

- Tests/SwiftKeyGenTests/FormatConversion/CheckReferenceFormatTest.swift
  - Test: understandReferenceFormat
  - Reason: Investigatory parsing to “understand reference format”; heavy print usage, no assertions. Intended for learning/debugging structure rather than validating code behavior.

- Tests/SwiftKeyGenTests/FormatConversion/Ed25519PEMTest.swift
  - Test: testEd25519PEMSupport
  - Reason: Prints type information and raw sizes from CryptoKit; contains no assertions and does not exercise project code paths. Investigatory/debug scaffold.

- Tests/SwiftKeyGenTests/Integration/CompareRealSSHKey.swift
  - Test: testCompareWithRealSSHKey
  - Reason: Attempts to parse a pasted OpenSSH private key; on failure, prints base64 and byte previews. No assertions verifying outcomes. Purely diagnostic.

- Tests/SwiftKeyGenTests/Integration/OpenSSLCompatTest.swift
  - Test: opensslIVTest
  - Reason: Labeled as an “investigation”; shells out to openssl and prints derived key/iv and file contents. No assertions verifying parity or correctness.

- Tests/SwiftKeyGenTests/Integration/SSHKeygenCipherTest.swift
  - Test: sshKeygenCipherTest
  - Reason: Loops over ciphers, shells out to ssh-keygen/openssl, and prints results (✅/❌); does not assert success/failure. Diagnostic compatibility probe.

- Tests/SwiftKeyGenTests/FormatConversion/PEMParserTests.swift
  - Test: testParsePEMStructure
  - Reason: Entire body is commented with a TODO; currently has no assertions and doesn’t exercise code. Placeholder/debug scaffold.

- Tests/SwiftKeyGenTests/Utilities/RandomArtTests.swift
  - Test: printExample
  - Reason: Explicitly for “visual verification”; prints example art and fingerprint. Minimal assertion on presence of characters, redundant with other structural tests.

- Tests/SwiftKeyGenTests/Cryptography/EVPBytesToKeyTest.swift
  - Test: evpBytesToKeyValidation
  - Reason: Traces EVP_BytesToKey step-by-step with extensive prints and shows “expected” values in comments; no assertions to enforce correctness. Investigatory/debug aid.

Notes
- The above were identified by reading each test file line-by-line and flagging cases with one or more of: no #expect assertions, extensive print-based inspection, TODO placeholders, or “investigation/understand/compare” intent without verification.
- Other tests that include occasional prints but also contain clear assertions were not included here, as they provide verifiable coverage.

