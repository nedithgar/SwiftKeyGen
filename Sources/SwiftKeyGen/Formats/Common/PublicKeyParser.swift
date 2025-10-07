import Foundation
import Crypto

/// A convenience façade that detects, parses and validates SSH public keys across
/// the text formats supported by SwiftKeyGen (OpenSSH one‑line format and
/// RFC4716 / SSH2 public key file format).
///
/// Use `PublicKeyParser` when you have an unknown public key string and need to:
///  - Determine the `KeyType`
///  - Extract the canonical SSH binary blob (for fingerprinting / storage)
///  - Validate the internal structure of the blob against the expected key type
///  - Produce a standardized fingerprint (MD5, SHA256, SHA512)
///
/// Parsing always returns the raw SSH wire representation (the same bytes that
/// appear in the base64 portion of an OpenSSH public key). This is the input to
/// fingerprint algorithms and further decoding (e.g. converting to other output
/// formats or embedding in certificates).
public struct PublicKeyParser {
    /// Returns `true` if the provided string conforms to the RFC4716 (SSH2) public
    /// key file format (BEGIN SSH2 PUBLIC KEY / END SSH2 PUBLIC KEY block with
    /// optional headers).
    ///
    /// - Parameter keyString: The candidate textual public key.
    /// - Returns: `true` when the string matches RFC4716 structure; otherwise `false`.
    public static func isRFC4716Format(_ keyString: String) -> Bool {
        return RFC4716Parser.isFormat(keyString)
    }

    /// Detects the `KeyType` encoded in an OpenSSH one‑line or RFC4716 public key string.
    ///
    /// Detection is resilient—failure to parse (corrupt base64, mismatched headers)
    /// results in `nil` rather than throwing. Use this when you only need the type and
    /// want a lightweight probe before full parsing.
    ///
    /// - Parameter publicKeyString: The raw text of the public key (either format).
    /// - Returns: The detected `KeyType`, or `nil` if the format or key type cannot be determined.
    public static func detectKeyType(from publicKeyString: String) -> KeyType? {
        if isRFC4716Format(publicKeyString) {
            // Decode the RFC4716 block to extract the type
            if let parsed = try? RFC4716Parser.parse(publicKeyString) {
                return parsed.type
            }
            return nil
        } else {
            return OpenSSHPublicKeyParser.detectKeyType(from: publicKeyString)
        }
    }

    /// Parses an OpenSSH one‑line public key string (e.g. "ssh-ed25519 AAAAC3... comment")
    /// into its structured components.
    ///
    /// - Parameter publicKeyString: The OpenSSH public key string.
    /// - Returns: A tuple containing:
    ///   - type: The `KeyType` extracted from the prefix / binary blob.
    ///   - data: The canonical SSH binary encoding (type length + type + key fields).
    ///   - comment: The trailing comment portion if present.
    /// - Throws: `SSHKeyError.invalidFormat` or other `SSHKeyError` cases surfaced by the
    ///           underlying OpenSSH parser when the string is malformed.
    /// - SeeAlso: ``parseAnyFormat(_:)`` for format‑agnostic parsing.
    public static func parsePublicKey(_ publicKeyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
        return try OpenSSHPublicKeyParser.parse(publicKeyString)
    }

    /// Parses an RFC4716 (SSH2) public key block.
    ///
    /// - Parameter rfc4716String: The full block including BEGIN/END delimiters.
    /// - Returns: A tuple `(type, data, comment)` where `comment` is derived from the
    ///            optional Comment header when present.
    /// - Throws: `SSHKeyError.invalidFormat` or `SSHKeyError.invalidKeyData` if the block
    ///           cannot be decoded or its contents do not match expectations.
    /// - Note: Header key/value pairs beyond the standard `Comment` are currently ignored.
    public static func parseRFC4716(_ rfc4716String: String) throws -> (type: KeyType, data: Data, comment: String?) {
        return try RFC4716Parser.parse(rfc4716String)
    }

    /// Parses a public key provided in either OpenSSH or RFC4716 textual format.
    ///
    /// This is a convenience wrapper that auto‑detects RFC4716; if not matched it
    /// assumes OpenSSH single‑line format.
    ///
    /// - Parameter keyString: The raw public key string.
    /// - Returns: The `(type, data, comment)` tuple as described in ``parsePublicKey(_:)``.
    /// - Throws: Any error thrown by ``parsePublicKey(_:)`` or ``parseRFC4716(_:)``.
    /// - Important: If detection chooses the wrong branch due to a malformed header,
    ///              the thrown error will indicate invalid format/data.
    public static func parseAnyFormat(_ keyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
        if isRFC4716Format(keyString) {
            return try parseRFC4716(keyString)
        } else {
            return try parsePublicKey(keyString)
        }
    }

    /// Validates that a decoded SSH public key binary blob matches the structural
    /// requirements for the declared `KeyType`.
    ///
    /// This performs a shallow syntactic inspection (field ordering, length sanity
    /// checks, curve name matching). It does not perform *cryptographic* validation
    /// (e.g. point-on-curve checks beyond size, RSA modulus primality, etc.). Those
    /// deeper assurances are deferred to their respective key implementations when
    /// constructing concrete key objects.
    ///
    /// - Parameters:
    ///   - data: The canonical SSH public key binary blob (as extracted from an OpenSSH line or RFC4716 block).
    ///   - type: The expected `KeyType`.
    /// - Throws: `SSHKeyError.invalidKeyData` if structure, lengths, or embedded type markers do not align.
    /// - SeeAlso: ``parseAnyFormat(_:)`` which produces the `data` input for this routine.
    public static func validatePublicKeyData(_ data: Data, type: KeyType) throws {
        var decoder = SSHDecoder(data: data)

        // Verify key type in data matches
        let encodedType = try decoder.decodeString()
        guard encodedType == type.rawValue else {
            throw SSHKeyError.invalidKeyData
        }

        // Validate key-specific data
        switch type {
        case .ed25519:
            let publicKeyBytes = try decoder.decodeData()
            guard publicKeyBytes.count == 32 else {
                throw SSHKeyError.invalidKeyData
            }

        case .rsa:
            let exponent = try decoder.decodeData()
            let modulus = try decoder.decodeData()
            guard !exponent.isEmpty && !modulus.isEmpty else {
                throw SSHKeyError.invalidKeyData
            }

        case .ecdsa256, .ecdsa384, .ecdsa521:
            let curveIdentifier = try decoder.decodeString()
            let expectedCurve: String
            let expectedKeySize: Int

            switch type {
            case .ecdsa256:
                expectedCurve = "nistp256"
                expectedKeySize = 65 // 0x04 + 32 + 32
            case .ecdsa384:
                expectedCurve = "nistp384"
                expectedKeySize = 97 // 0x04 + 48 + 48
            case .ecdsa521:
                expectedCurve = "nistp521"
                expectedKeySize = 133 // 0x04 + 66 + 66
            default:
                throw SSHKeyError.invalidKeyData
            }

            guard curveIdentifier == expectedCurve else {
                throw SSHKeyError.invalidKeyData
            }

            let publicKeyBytes = try decoder.decodeData()
            guard publicKeyBytes.count == expectedKeySize else {
                throw SSHKeyError.invalidKeyData
            }
        }

        // Ensure no extra data
        guard !decoder.hasMoreData else {
            throw SSHKeyError.invalidKeyData
        }
    }

    /// Generates a human‑readable fingerprint for a public key provided in either
    /// OpenSSH or RFC4716 textual format.
    ///
    /// The underlying SSH binary blob (decoded base64) is hashed using the selected
    /// algorithm. Output formatting matches OpenSSH conventions:
    ///  - MD5: Hex pairs separated by colons (legacy format)
    ///  - SHA256 / SHA512: Prefixed with the algorithm name and base64 (no padding)
    ///
    /// - Parameters:
    ///   - keyString: The textual public key (OpenSSH or RFC4716).
    ///   - hash: The hash algorithm to use. Defaults to `.sha256` (recommended).
    /// - Returns: The fingerprint string (e.g. `SHA256:abc123...`).
    /// - Throws: Any error thrown while parsing the key (see ``parseAnyFormat(_:)``).
    /// - SeeAlso: `HashFunction` for available algorithms.
    public static func fingerprint(from keyString: String, hash: HashFunction = .sha256) throws -> String {
        let (_, keyData, _) = try parseAnyFormat(keyString)

        switch hash {
        case .md5:
            let digest = Insecure.MD5.hash(data: keyData)
            return Data(digest).hexEncodedString(separator: ":")

        case .sha256:
            let digest = SHA256.hash(data: keyData)
            let base64 = Data(digest).base64EncodedStringStrippingPadding()
            return "SHA256:" + base64

        case .sha512:
            let digest = SHA512.hash(data: keyData)
            let base64 = Data(digest).base64EncodedStringStrippingPadding()
            return "SHA512:" + base64
        }
    }
}
