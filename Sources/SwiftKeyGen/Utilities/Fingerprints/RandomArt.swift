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
    /// - Important: The MD5 hash usage here is for visual parity only; do not rely on MD5 elsewhere for
    ///   security decisions.
    public static func generate(for key: any SSHKey) -> String {
        let fingerprint = key.fingerprint(hash: .md5, format: .hex)
        let hashData = extractHashBytes(from: fingerprint)
        
        return generate(
            hashData: hashData,
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
        let hashData = extractHashBytes(from: fingerprint)
        return generate(hashData: hashData, keyType: keyType, keySize: keySize)
    }
    
    private static func generate(hashData: Data, keyType: String, keySize: Int) -> String {
        var field = Array(repeating: Array(repeating: 0, count: fieldWidth), count: fieldHeight)
        var x = fieldWidth / 2
        var y = fieldHeight / 2
        
        // Process each byte of the hash
        for byte in hashData {
            for i in 0..<4 {
                let direction = (byte >> (6 - i * 2)) & 0x03
                
                // Move based on direction (0=NW, 1=NE, 2=SW, 3=SE)
                switch direction {
                case 0: // NW
                    x = max(0, x - 1)
                    y = max(0, y - 1)
                case 1: // NE
                    x = min(fieldWidth - 1, x + 1)
                    y = max(0, y - 1)
                case 2: // SW
                    x = max(0, x - 1)
                    y = min(fieldHeight - 1, y + 1)
                case 3: // SE
                    x = min(fieldWidth - 1, x + 1)
                    y = min(fieldHeight - 1, y + 1)
                default:
                    break
                }
                
                // Increment visit count
                field[y][x] = min(field[y][x] + 1, augmentationString.count - 1)
            }
        }
        
        // Mark start and end positions
        let startX = fieldWidth / 2
        let startY = fieldHeight / 2
        let endX = x
        let endY = y
        
        // Build the output
        var output = ""
        
        // Header
        let header = keySize > 0 ? "[\(keyType) \(keySize)]" : "[\(keyType)]"
        let padding = (fieldWidth + 2 - header.count) / 2
        output += "+" + String(repeating: "-", count: padding) + header
        output += String(repeating: "-", count: fieldWidth + 2 - padding - header.count) + "+\n"
        
        // Field
        for (row, line) in field.enumerated() {
            output += "|"
            for (col, visits) in line.enumerated() {
                if row == startY && col == startX {
                    output += "S"
                } else if row == endY && col == endX {
                    output += "E"
                } else {
                    let index = min(visits, augmentationString.count - 1)
                    let charIndex = augmentationString.index(augmentationString.startIndex, offsetBy: index)
                    output += String(augmentationString[charIndex])
                }
            }
            output += "|\n"
        }
        
        // Footer
        output += "+" + String(repeating: "-", count: fieldWidth + 2) + "+"
        
        return output
    }
    
    private static func extractHashBytes(from fingerprint: String) -> Data {
        // Handle different fingerprint formats
        if fingerprint.hasPrefix("SHA256:") || fingerprint.hasPrefix("SHA512:") {
            // Base64 encoded hash
            let base64Part = String(fingerprint.split(separator: ":").last ?? "")
            return Data(base64Encoded: base64Part) ?? Data()
        } else {
            // MD5 hex format (xx:xx:xx:...)
            let hexString = fingerprint.replacingOccurrences(of: ":", with: "")
            var data = Data()
            var temp = ""
            
            for char in hexString {
                temp += String(char)
                if temp.count == 2 {
                    if let byte = UInt8(temp, radix: 16) {
                        data.append(byte)
                    }
                    temp = ""
                }
            }
            
            return data
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
        }
    }
}