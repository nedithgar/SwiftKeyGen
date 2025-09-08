import Foundation
import Crypto

/// Generate SSH randomart visualization for key fingerprints
public struct RandomArt {
    private static let fieldWidth = 17
    private static let fieldHeight = 9
    private static let augmentationString = " .o+=*BOX@%&#/^SE"
    
    /// Generate randomart visualization for a key
    public static func generate(for key: any SSHKey) -> String {
        let fingerprint = key.fingerprint(hash: .md5, format: .hex)
        let hashData = extractHashBytes(from: fingerprint)
        
        return generate(
            hashData: hashData,
            keyType: key.keyType.algorithmName,
            keySize: keySize(for: key)
        )
    }
    
    /// Generate randomart from fingerprint string
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