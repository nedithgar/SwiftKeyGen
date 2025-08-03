import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Compare Format Test")
struct CompareFormatTest {
    
    @Test("Compare our format with expected")
    func compareFormat() throws {
        // Generate a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Decode and examine the structure
        guard let pemString = String(data: serializedData, encoding: .utf8) else {
            throw SSHKeyError.invalidFormat
        }
        
        let lines = pemString.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inKey = false
        
        for line in lines {
            if line.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
                inKey = true
                continue
            }
            if line.contains("-----END OPENSSH PRIVATE KEY-----") {
                break
            }
            if inKey && !line.isEmpty {
                base64Lines.append(line)
            }
        }
        
        let base64String = base64Lines.joined()
        guard let keyData = Data(base64Encoded: base64String) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Print hex dump of first 100 bytes
        print("=== HEX DUMP OF SERIALIZED KEY ===")
        let hexDump = keyData.prefix(100).map { String(format: "%02x", $0) }.joined(separator: " ")
        print(hexDump)
        
        // Manually parse to see structure
        var offset = 0
        
        // Magic header (15 bytes)
        let magic = keyData.subdata(in: 0..<15)
        print("\nMagic (15 bytes): \(String(data: magic, encoding: .utf8)?.debugDescription ?? "invalid")")
        offset = 15
        
        // Read cipher name length
        if offset + 4 <= keyData.count {
            let cipherLenData = keyData.subdata(in: offset..<offset+4)
            let cipherLen = cipherLenData.withUnsafeBytes { bytes in
                return UInt32(bigEndian: bytes.load(as: UInt32.self))
            }
            print("Cipher name length: \(cipherLen)")
            offset += 4
            
            if offset + Int(cipherLen) <= keyData.count {
                let cipherData = keyData.subdata(in: offset..<offset+Int(cipherLen))
                print("Cipher name: \(String(data: cipherData, encoding: .utf8) ?? "invalid")")
                offset += Int(cipherLen)
            }
        }
        
        // Read KDF name length
        if offset + 4 <= keyData.count {
            let kdfLenData = keyData.subdata(in: offset..<offset+4)
            let kdfLen = kdfLenData.withUnsafeBytes { bytes in
                return UInt32(bigEndian: bytes.load(as: UInt32.self))
            }
            print("KDF name length: \(kdfLen)")
            offset += 4
            
            if offset + Int(kdfLen) <= keyData.count {
                let kdfData = keyData.subdata(in: offset..<offset+Int(kdfLen))
                print("KDF name: \(String(data: kdfData, encoding: .utf8) ?? "invalid")")
                offset += Int(kdfLen)
            }
        }
        
        // Read KDF data length
        if offset + 4 <= keyData.count {
            let kdfDataLenData = keyData.subdata(in: offset..<offset+4)
            let kdfDataLen = kdfDataLenData.withUnsafeBytes { bytes in
                return UInt32(bigEndian: bytes.load(as: UInt32.self))
            }
            print("KDF data length: \(kdfDataLen)")
            offset += 4 + Int(kdfDataLen)
        }
        
        // Number of keys
        if offset + 4 <= keyData.count {
            let numKeysData = keyData.subdata(in: offset..<offset+4)
            let numKeys = numKeysData.withUnsafeBytes { bytes in
                return UInt32(bigEndian: bytes.load(as: UInt32.self))
            }
            print("Number of keys: \(numKeys)")
            offset += 4
        }
        
        // Public key length
        if offset + 4 <= keyData.count {
            let pubKeyLenData = keyData.subdata(in: offset..<offset+4)
            let pubKeyLen = pubKeyLenData.withUnsafeBytes { bytes in
                return UInt32(bigEndian: bytes.load(as: UInt32.self))
            }
            print("Public key data length: \(pubKeyLen)")
            offset += 4
            
            // Show first few bytes of public key
            if offset + 20 <= keyData.count {
                let pubKeyPreview = keyData.subdata(in: offset..<offset+20)
                print("Public key preview: \(pubKeyPreview.map { String(format: "%02x", $0) }.joined(separator: " "))")
            }
        }
        
        print("\nCurrent offset: \(offset) of \(keyData.count) bytes")
    }
}