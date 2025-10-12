import Foundation
import Crypto

/// A generator for OpenSSH‑style ASCII "randomart" (Drunken Bishop) visualizations of key fingerprints.
///
/// Randomart provides a quick, coarse visual cue to help a human recognize whether a public key (or its
/// fingerprint) has changed unexpectedly (e.g. on first SSH connection vs. subsequent ones). While it is **not**
/// a cryptographic security control, it can surface accidental mismatches or obvious MITM scenarios to an
/// attentive user.
///
/// The implementation here mirrors the behavior and dimensions used by `ssh-keygen` (17×9 board, start/end
/// markers, and the canonical augmentation character sequence) while remaining self‑contained so it can be
/// reused anywhere inside the library (CLI, tests, or higher‑level tooling).
///
/// ### Usage
/// ```swift
/// // Generate a key pair (example – assuming synchronous API in this codebase)
/// let pair = try KeyGeneration.generateKeyPair(type: .ed25519)
/// // Produce the randomart from the private (or public) key
/// let art = RandomArt.generate(for: pair.privateKey)
/// print(art)
/// ```
///
/// - Note: MD5 is used here strictly for compatibility with OpenSSH randomart output expectations; the
///   library should continue to use modern hashes (e.g. SHA‑256) for security decisions elsewhere.
/// - SeeAlso: ``RandomArt/generate(for:)``, ``RandomArt/generate(from:keyType:keySize:)``
public struct RandomArt {
    private static let fieldWidth = 17
    private static let fieldHeight = 9
    private static let augmentationString = " .o+=*BOX@%&#/^SE"
    
    /// Generates an ASCII randomart visualization for the supplied SSH key.
    ///
    /// This convenience method derives the MD5 hexadecimal fingerprint (matching classic OpenSSH output)
    /// and then feeds it into the generic generator. The resulting string contains a header with the
    /// algorithm (and size when derivable), the 17×9 art body, and a footer border.
    ///
    /// - Parameter key: A concrete type conforming to ``SSHKey`` whose fingerprint will be visualized.
    /// - Returns: A multi‑line string containing the framed randomart block.
    /// - Important: Matches modern OpenSSH behavior: uses a SHA‑256 digest for
    ///   the randomart walk and embeds the hash label in the footer. Do not
    ///   rely on this for security decisions.
    public static func generate(for key: any SSHKey) -> String {
        // Use SHA-256 digest to mirror `ssh-keygen -lv` output
        let fingerprint = key.fingerprint(hash: .sha256, format: .base64)
        let (hashData, hashLabel) = extractHashBytesAndLabel(from: fingerprint)

        return generate(
            hashData: hashData,
            hashLabel: hashLabel,
            keyType: key.keyType.algorithmName,
            keySize: keySize(for: key)
        )
    }
    
    /// Generates randomart directly from a fingerprint string.
    ///
    /// Accepts the common OpenSSH fingerprint encodings:
    /// - MD5 hex with colons (e.g. `aa:bb:cc:...`)
    /// - Base64 forms prefixed with `SHA256:` or `SHA512:` (as output by modern `ssh-keygen`)
    ///
    /// The provided `keyType` and `keySize` values are used only for aesthetic labeling in the header; they
    /// do not affect the walk.
    ///
    /// - Parameters:
    ///   - fingerprint: A fingerprint string in one of the supported OpenSSH formats.
    ///   - keyType: A short label describing the algorithm (e.g. "ED25519", "RSA"). Defaults to `"Key"`.
    ///   - keySize: Nominal key size in bits for header display. Defaults to `0` (omitted).
    /// - Returns: The fully rendered randomart ASCII block.
    public static func generate(from fingerprint: String, keyType: String = "Key", keySize: Int = 0) -> String {
        let (hashData, hashLabel) = extractHashBytesAndLabel(from: fingerprint)
        return generate(hashData: hashData, hashLabel: hashLabel, keyType: keyType, keySize: keySize)
    }
    
    private static func generate(hashData: Data, hashLabel: String, keyType: String, keySize: Int) -> String {
        var field = Array(repeating: Array(repeating: 0, count: fieldWidth), count: fieldHeight)
        var x = fieldWidth / 2
        var y = fieldHeight / 2

        // OpenSSH uses LSB-first processing of 2-bit commands per byte.
        // Move vector: x += (bit0 ? +1 : -1); y += (bit1 ? +1 : -1)
        let augmentationCount = augmentationString.count
        let maxDuringWalk = augmentationCount - 3 // prevent reaching 'S'/'E' indices

        for byte in hashData {
            var b = byte
            for _ in 0..<4 {
                let bit0 = (b & 0x01) != 0
                let bit1 = (b & 0x02) != 0

                x += bit0 ? 1 : -1
                y += bit1 ? 1 : -1

                x = min(max(0, x), fieldWidth - 1)
                y = min(max(0, y), fieldHeight - 1)

                if field[y][x] < maxDuringWalk {
                    field[y][x] += 1
                }
                b >>= 2
            }
        }

        // Mark starting point and end point using indices of 'S' and 'E'
        let startX = fieldWidth / 2
        let startY = fieldHeight / 2
        let endX = x
        let endY = y
        field[startY][startX] = augmentationCount - 2
        field[endY][endX] = augmentationCount - 1

        // Build the output
        var output = ""

        // Header: centered [TYPE SIZE] (or [TYPE] if too long)
        let titleBody: String = {
            let full = keySize > 0 ? "[\(keyType) \(keySize)]" : "[\(keyType)]"
            if full.count <= fieldWidth { return full }
            return "[\(keyType)]"
        }()
        let leftPad = (fieldWidth - titleBody.count) / 2
        output += "+" + String(repeating: "-", count: leftPad) + titleBody
        output += String(repeating: "-", count: fieldWidth - leftPad - titleBody.count) + "+\n"

        // Field content
        for row in 0..<fieldHeight {
            output += "|"
            for col in 0..<fieldWidth {
                let visits = field[row][col]
                let idx = augmentationString.index(augmentationString.startIndex, offsetBy: visits)
                output += String(augmentationString[idx])
            }
            output += "|\n"
        }

        // Footer: centered [HASHLABEL]
        let hashBody = "[\(hashLabel)]"
        let leftPadFooter = (fieldWidth - hashBody.count) / 2
        output += "+" + String(repeating: "-", count: leftPadFooter) + hashBody
        output += String(repeating: "-", count: fieldWidth - leftPadFooter - hashBody.count) + "+"

        return output
    }
    
    private static func extractHashBytesAndLabel(from fingerprint: String) -> (Data, String) {
        // Handle different fingerprint formats
        if fingerprint.hasPrefix("SHA256:") || fingerprint.hasPrefix("SHA512:") {
            // Base64 encoded hash
            let comps = fingerprint.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true)
            let label = String(comps.first ?? "SHA256")
            let base64Part = comps.count > 1 ? String(comps[1]) : ""
            let padLen = (4 - (base64Part.count % 4)) % 4
            let padded = base64Part + String(repeating: "=", count: padLen)
            return (Data(base64Encoded: padded, options: .ignoreUnknownCharacters) ?? Data(), label)
        } else if fingerprint.contains(":") { // MD5 hex with colons
            let hexString = fingerprint.replacingOccurrences(of: ":", with: "")
            var data = Data()
            var temp = ""
            for char in hexString {
                temp += String(char)
                if temp.count == 2 {
                    if let byte = UInt8(temp, radix: 16) { data.append(byte) }
                    temp = ""
                }
            }
            return (data, "MD5")
        } else {
            // Fallback: treat as raw hex without separators
            var data = Data()
            var temp = ""
            for char in fingerprint {
                temp += String(char)
                if temp.count == 2 {
                    if let byte = UInt8(temp, radix: 16) { data.append(byte) }
                    temp = ""
                }
            }
            return (data, "MD5")
        }
    }
    
    private static func keySize(for key: any SSHKey) -> Int {
        switch key.keyType {
        case .ed25519:
            return 256
        case .rsa:
            return 2048 // Default, would need to extract from key
        case .ecdsa256:
            return 256
        case .ecdsa384:
            return 384
        case .ecdsa521:
            return 521
        default:
            return 0
        }
    }
}
