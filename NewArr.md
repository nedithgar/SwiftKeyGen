SwiftKeyGen — Proposed Source Layout and Moves

Goals
- Clarify domain boundaries (Keys, Formats, Certificates, Cryptography, SSH, Utilities, Core).
- Keep public vs. private key types distinct and colocated with related helpers.
- Group format-specific code under Formats, including SSH wire encoding.
- Keep reusable helpers under Extensions; move full crypto primitives out of Extensions.
- Preserve CLI separation; keep the library free of CLI-only concerns.

Top‑Level Targets (unchanged)
- Sources/SwiftKeyGen/        Library
- Sources/SwiftKeyGenCLI/     CLI
- Sources/HMACVerifyTool/     CLI utility

Proposed Layout (Sources/SwiftKeyGen)

Core/
- KeyGeneration.swift                // SwiftKeyGen factories
- KeyManager.swift                   // Key file ops (passphrase, info)
- KeyPair.swift                      // Value container
- KeyType.swift                      // Algorithms + defaults
- SSHKeyError.swift                  // Central error enum

Keys/
- Protocols/
  - SSHKey.swift                     // SSHKey + SSHKeyGenerator + HashFunction/FingerprintFormat
  - SSHPublicKey.swift               // extracted protocol from PublicKeys (see mapping)
- Private/
  - RSAKey.swift
  - Ed25519Key.swift
  - ECDSAKey.swift
- Public/
  - SSHPublicKeys.swift              // Ed25519PublicKey, RSAPublicKey, ECDSAPublicKey

Certificates/
- Models/
  - SSHCertificate.swift             // moved from SSH/
- Authority/
  - CertificateAuthority.swift
- Parser/
  - CertificateParser.swift
- Verifier/
  - CertificateVerifier.swift
- Manager/
  - CertificateManager.swift

Formats/
- SSH/
  - SSHEncoding.swift                // SSHEncoder/SSHDecoder (moved from SSH/)
- OpenSSH/
  - OpenSSHPrivateKey.swift
- RFC4716/
  - RFC4716Parser.swift              // split from KeyParser (see mapping)
- PEM/
  - PEMParser.swift
  - PEMEncryption.swift
  - RSA+PEM.swift
  - Ed25519+PEM.swift
- PKCS/
  - PKCS8Encryption.swift
- DER/
  - RSA+DER.swift
  - ECDSA+SEC1.swift
- ASN1/
  - ASN1Parser.swift
- Common/
  - PublicKeyParser.swift            // unified wrapper that dispatches to OpenSSH/RFC4716

Conversion/
- KeyConversionManager.swift
- KeyConverter.swift                 // rename from KeyConversion.swift

Cryptography/
- Primitives/
  - RSA/
    - InsecureRSA.swift             // moved from Extensions/
  - Blowfish/
    - Blowfish.swift
- KDF/
  - BCryptPBKDF.swift               // rename from BCrypt.swift
- Ciphers/
  - AES/
    - AESEngine.swift
    - AESCTR.swift
    - AESCBC.swift
    - AESGCM.swift
  - ChaCha20Poly1305.swift
  - TripleDESCBC.swift
  - Cipher.swift

SSH/
- KnownHosts/
  - KnownHosts.swift

Utilities/
- Encoding/
  - ECDSAEncoding.swift
- Fingerprints/
  - BubbleBabble.swift
  - RandomArt.swift
- IO/
  - KeyFileManager.swift
- Batch/
  - BatchKeyGenerator.swift

Extensions/
- Data.swift
- InlineArray.swift
- Span.swift


Moves and Renames (Old → New)

<!-- Core
- Sources/SwiftKeyGen/Core/KeyGeneration.swift → Core/KeyGeneration.swift
- Sources/SwiftKeyGen/Core/KeyManager.swift → Core/KeyManager.swift
- Sources/SwiftKeyGen/Core/KeyPair.swift → Core/KeyPair.swift
- Sources/SwiftKeyGen/Core/KeyType.swift → Core/KeyType.swift
- Sources/SwiftKeyGen/Core/SSHKeyError.swift → Core/SSHKeyError.swift -->

Keys
- Sources/SwiftKeyGen/Keys/SSHKey.swift → Keys/Protocols/SSHKey.swift
- Sources/SwiftKeyGen/Keys/RSAKey.swift → Keys/Private/RSAKey.swift
- Sources/SwiftKeyGen/Keys/Ed25519Key.swift → Keys/Private/Ed25519Key.swift
- Sources/SwiftKeyGen/Keys/ECDSAKey.swift → Keys/Private/ECDSAKey.swift
- Sources/SwiftKeyGen/SSH/PublicKeys.swift → Keys/Public/SSHPublicKeys.swift
  - Additionally extract `SSHPublicKey` protocol to Keys/Protocols/SSHPublicKey.swift

<!-- Certificates
- Sources/SwiftKeyGen/SSH/SSHCertificate.swift → Certificates/Models/SSHCertificate.swift
- Sources/SwiftKeyGen/Certificates/CertificateAuthority.swift → Certificates/Authority/CertificateAuthority.swift
- Sources/SwiftKeyGen/Certificates/CertificateParser.swift → Certificates/Parser/CertificateParser.swift
- Sources/SwiftKeyGen/Certificates/CertificateVerifier.swift → Certificates/Verifier/CertificateVerifier.swift
- Sources/SwiftKeyGen/Certificates/CertificateManager.swift → Certificates/Manager/CertificateManager.swift -->

<!-- Formats
- Sources/SwiftKeyGen/SSH/SSHEncoding.swift → Formats/SSH/SSHEncoding.swift
- Sources/SwiftKeyGen/Formats/OpenSSH/OpenSSHPrivateKey.swift → Formats/OpenSSH/OpenSSHPrivateKey.swift
- Sources/SwiftKeyGen/Formats/PEM/PEMParser.swift → Formats/PEM/PEMParser.swift
- Sources/SwiftKeyGen/Formats/PEM/PEMEncryption.swift → Formats/PEM/PEMEncryption.swift
- Sources/SwiftKeyGen/Formats/PEM/RSA+PEM.swift → Formats/PEM/RSA+PEM.swift
- Sources/SwiftKeyGen/Formats/PEM/Ed25519+PEM.swift → Formats/PEM/Ed25519+PEM.swift
- Sources/SwiftKeyGen/Formats/PKCS/PKCS8Encryption.swift → Formats/PKCS/PKCS8Encryption.swift
- Sources/SwiftKeyGen/Formats/DER/RSA+DER.swift → Formats/DER/RSA+DER.swift
- Sources/SwiftKeyGen/Formats/DER/ECDSA+SEC1.swift → Formats/DER/ECDSA+SEC1.swift
- Sources/SwiftKeyGen/Formats/ASN1/ASN1Parser.swift → Formats/ASN1/ASN1Parser.swift
- Sources/SwiftKeyGen/Utilities/KeyParser.swift → Formats/Common/PublicKeyParser.swift
  - Option A (preferred): split into `Formats/OpenSSH/OpenSSHPublicKeyParser.swift` and `Formats/RFC4716/RFC4716Parser.swift`, with `Formats/Common/PublicKeyParser.swift` as a façade.
  - Option B (minimal diff): move as-is to `Formats/Common/PublicKeyParser.swift` and adjust call sites. -->

<!-- Conversion
- Sources/SwiftKeyGen/Conversion/KeyConversionManager.swift → Conversion/KeyConversionManager.swift
- Sources/SwiftKeyGen/Conversion/KeyConversion.swift → Conversion/KeyConverter.swift -->

<!-- Cryptography
- Sources/SwiftKeyGen/Cryptography/Blowfish.swift → Cryptography/Primitives/Blowfish/Blowfish.swift
- Sources/SwiftKeyGen/Cryptography/BCrypt.swift → Cryptography/KDF/BCryptPBKDF.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/Cipher.swift → Cryptography/Ciphers/Cipher.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/AES/AESEngine.swift → Cryptography/Ciphers/AES/AESEngine.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/AES/AESCTR.swift → Cryptography/Ciphers/AES/AESCTR.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/AES/AESCBC.swift → Cryptography/Ciphers/AES/AESCBC.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/AES/AESGCM.swift → Cryptography/Ciphers/AES/AESGCM.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/ChaCha20Poly1305.swift → Cryptography/Ciphers/ChaCha20Poly1305.swift
- Sources/SwiftKeyGen/Cryptography/Ciphers/TripleDESCBC.swift → Cryptography/Ciphers/TripleDESCBC.swift
- Sources/SwiftKeyGen/Extensions/Insecure+RSA.swift → Cryptography/Primitives/RSA/InsecureRSA.swift -->

<!-- SSH
- Sources/SwiftKeyGen/SSH/KnownHosts.swift → SSH/KnownHosts/KnownHosts.swift -->

<!-- Utilities
- Sources/SwiftKeyGen/Utilities/ECDSAEncoding.swift → Utilities/Encoding/ECDSAEncoding.swift
- Sources/SwiftKeyGen/Utilities/KeyFileManager.swift → Utilities/IO/KeyFileManager.swift
- Sources/SwiftKeyGen/Utilities/BubbleBabble.swift → Utilities/Fingerprints/BubbleBabble.swift
- Sources/SwiftKeyGen/Utilities/RandomArt.swift → Utilities/Fingerprints/RandomArt.swift
- Sources/SwiftKeyGen/Utilities/BatchKeyGenerator.swift → Utilities/Batch/BatchKeyGenerator.swift -->

Extensions
- Sources/SwiftKeyGen/Extensions/Data.swift → Extensions/Data.swift
- Sources/SwiftKeyGen/Extensions/InlineArray.swift → Extensions/InlineArray.swift
- Sources/SwiftKeyGen/Extensions/Span.swift → Extensions/Span.swift


Rationale and Notes
- Keys vs. Formats: Keep wire/PEM/DER concerns under Formats. SSHEncoder/SSHDecoder belong with formats.
- Certificates: Centralize SSH certificate model+authority+parsing+verification to reduce cross-folder coupling.
- Public vs. Private keys: Split or at least clearly group; SSHPublicKey protocol sits with key protocols.
- Cryptography: Move full primitives (RSA, Blowfish) under Cryptography; Extensions remains for lightweight helpers only.
- Utilities: Group by concern (encoding, fingerprints, batch, IO). Keep ECDSAEncoding as a small helper under Utilities/Encoding.
- Conversion: Rename KeyConversion.swift → KeyConverter.swift to match type name and improve discoverability.
- SSH: Keep host file management (KnownHosts) in SSH/, separate from certificate model which moves to Certificates/.

Follow‑Ups After Moving Files
- Update imports where necessary (e.g., `SSHPublicKey` protocol path, SSHEncoding path).
- If splitting KeyParser, adjust callers: KeyConversionManager, CLI, and any Utilities that reference it.
- Consider minor type relocations:
  - If desired, move `publicOnlyKey()` extension (currently in PublicKeys) alongside Keys/Protocols.
  - Optionally split SSHPublicKeys.swift into three files for parity with private key files.
- Validate OpenSSH private key code still imports SSHEncoder from new Formats/SSH path.
- No SPM target changes are required; directory moves within the target are sufficient.

CLI Targets (unchanged)
- Sources/SwiftKeyGenCLI/main.swift
- Sources/HMACVerifyTool/main.swift

