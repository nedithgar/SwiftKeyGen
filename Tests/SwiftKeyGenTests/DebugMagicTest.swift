import Testing
import Foundation
@testable import SwiftKeyGen

struct DebugMagicTest {
    @Test("Debug magic header parsing")
    func testDebugMagicParsing() throws {
        // Real SSH key base64
        let base64 = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBt5QetJQ8QH1C1dVhI6wqJSSsb1UVKbwQhFjPLeRGJMAAAAJhMCadETAmnRAAAAAtzc2gtZWQyNTUxOQAAACBt5QetJQ8QH1C1dVhI6wqJSSsb1UVKbwQhFjPLeRGJMAAAAEDbpuLhSq2OMQF3PO0m3/pJAFmBYh5pLdh+wYnWdPPLBm3lB60lDxAfULV1WEjrColJKxvVRUpvBCEWM8t5EYkwAAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ=="
        
        guard let data = Data(base64Encoded: base64) else {
            Issue.record("Failed to decode base64")
            return
        }
        
        print("Total data length: \(data.count)")
        
        // Check magic header
        let magicString = "openssh-key-v1\0"
        let magicData = Data(magicString.utf8)
        print("Expected magic length: \(magicData.count)")
        print("Expected magic bytes: \(magicData.map { String(format: "%02x", $0) }.joined(separator: " "))")
        
        // Check actual bytes
        print("Actual first 20 bytes: \(data.prefix(20).map { String(format: "%02x", $0) }.joined(separator: " "))")
        
        // After magic (15 bytes), what comes next?
        var offset = 15
        
        // Next should be cipher name length (4 bytes)
        let cipherLengthBytes = data.subdata(in: offset..<offset+4)
        let cipherLength = cipherLengthBytes.withUnsafeBytes { bytes in
            return UInt32(bigEndian: bytes.load(as: UInt32.self))
        }
        print("\nCipher name length: \(cipherLength)")
        offset += 4
        
        // Cipher name
        let cipherName = String(data: data.subdata(in: offset..<offset+Int(cipherLength)), encoding: .utf8) ?? "invalid"
        print("Cipher name: '\(cipherName)'")
        offset += Int(cipherLength)
        
        // Next is KDF name length
        let kdfLengthBytes = data.subdata(in: offset..<offset+4)
        let kdfLength = kdfLengthBytes.withUnsafeBytes { bytes in
            return UInt32(bigEndian: bytes.load(as: UInt32.self))
        }
        print("\nKDF name length: \(kdfLength)")
        offset += 4
        
        // KDF name
        let kdfName = String(data: data.subdata(in: offset..<offset+Int(kdfLength)), encoding: .utf8) ?? "invalid"
        print("KDF name: '\(kdfName)'")
    }
}