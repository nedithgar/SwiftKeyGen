import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Random Art Unit Tests", .tags(.unit))
struct RandomArtUnitTests {
    
    // Fast: does not generate keys
    @Test("Renders art from MD5 fingerprint with header")
    func fromFingerprintRendersHeaderAndBody() throws {
        // Test with MD5 fingerprint
        let md5Fingerprint = "43:51:43:a1:b5:fc:8b:b7:0a:3a:a9:b1:0f:66:73:a8"
        let art = RandomArt.generate(from: md5Fingerprint, keyType: "RSA", keySize: 2048)
        
        #expect(art.contains("[RSA 2048]"))
        
        // Verify the art is generated
        let lines = art.split(separator: "\n")
        #expect(lines.count == 11)
        // Start/End markers always present
        let fieldContent = lines[1...9].joined()
        #expect(fieldContent.contains("S"))
        #expect(fieldContent.contains("E"))
    }

    @Test("Header centering across non-RSA labels")
    func headerCenteringAcrossNonRSALabels() {
        let md5Fingerprint = "43:51:43:a1:b5:fc:8b:b7:0a:3a:a9:b1:0f:66:73:a8"
        let cases: [(String, Int)] = [
            ("ED25519", 256),
            ("ECDSA", 256),
            ("ECDSA", 521)
        ]
        for (label, bits) in cases {
            let header = "[\(label) \(bits)]"
            let art = RandomArt.generate(from: md5Fingerprint, keyType: label, keySize: bits)
            let lines = art.split(separator: "\n")
            #expect(lines.count == 11)
            let line = String(lines[0])
            #expect(line.hasPrefix("+"))
            #expect(line.hasSuffix("+"))
            guard let range = line.range(of: header) else {
                Issue.record("Header not found in random art header line for \(header)")
                continue
            }
            let leftPart = line[line.index(after: line.startIndex)..<range.lowerBound]
            let rightPart = line[range.upperBound..<line.index(before: line.endIndex)]
            let leftHyphens = leftPart.filter { $0 == "-" }.count
            let rightHyphens = rightPart.filter { $0 == "-" }.count
            #expect(abs(leftHyphens - rightHyphens) <= 1)
            // Footer length matches header length
            #expect(lines[0].count == lines[10].count)
        }
    }

    @Test("Header centering for RSA label")
    func headerCenteringForRSAFingerprint() {
        let md5Fingerprint = "43:51:43:a1:b5:fc:8b:b7:0a:3a:a9:b1:0f:66:73:a8"
        let label = "RSA"
        let bits = 2048
        let header = "[\(label) \(bits)]"
        let art = RandomArt.generate(from: md5Fingerprint, keyType: label, keySize: bits)
        let lines = art.split(separator: "\n")
        #expect(lines.count == 11)
        let line = String(lines[0])
        #expect(line.hasPrefix("+"))
        #expect(line.hasSuffix("+"))
        guard let range = line.range(of: header) else {
            Issue.record("Header not found in random art header line for \(header)")
            return
        }
        let leftPart = line[line.index(after: line.startIndex)..<range.lowerBound]
        let rightPart = line[range.upperBound..<line.index(before: line.endIndex)]
        let leftHyphens = leftPart.filter { $0 == "-" }.count
        let rightHyphens = rightPart.filter { $0 == "-" }.count
        #expect(abs(leftHyphens - rightHyphens) <= 1)
        #expect(lines[0].count == lines[10].count)
    }

    @Test("Renders art from SHA256 base64 fingerprint")
    func fromSHA256FingerprintRenders() {
        let bytes = Data((0..<32).map(UInt8.init))
        let fp = "SHA256:\(bytes.base64EncodedString())"
        let art = RandomArt.generate(from: fp, keyType: "ED25519", keySize: 256)
        let lines = art.split(separator: "\n")
        #expect(lines.count == 11)
        let content = lines[1...9].joined()
        #expect(content.contains("S"))
        #expect(content.contains("E"))
    }
    
    // Single key generation
    @Test("Generates art structure for ED25519 key")
    func generatesArtStructureForEd25519() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let art = RandomArt.generate(for: key)
        
        // Verify structure
        let lines = art.split(separator: "\n")
        #expect(lines.count == 11) // Header + 9 rows + footer
        
        guard lines.count >= 11 else {
            Issue.record("Random art has incorrect number of lines: \(lines.count)")
            return
        }
        
        // Verify header contains key type/size
        #expect(lines[0].contains("[ED25519 256]"))
        
        // Verify borders
        #expect(lines[0].hasPrefix("+"))
        #expect(lines[0].hasSuffix("+"))
        #expect(lines[10].hasPrefix("+"))
        #expect(lines[10].hasSuffix("+"))
        
        // Verify field rows
        for i in 1...9 {
            #expect(lines[i].hasPrefix("|"))
            #expect(lines[i].hasSuffix("|"))
            #expect(lines[i].count == 19) // |<17 chars>|
        }
        
        // Verify S and E markers exist
        let fieldContent = lines[1...9].joined()
        #expect(fieldContent.contains("S"))
        #expect(fieldContent.contains("E"))
    }
    
    // Two key generations (heavier)
    @Test("Distinct keys produce distinct random art")
    func differentKeysYieldDifferentArt() throws {
        let key1 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let key2 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let art1 = RandomArt.generate(for: key1)
        let art2 = RandomArt.generate(for: key2)
        
        #expect(art1 != art2)
    }
    
    // Multiple key types (heaviest)
    @Test("Header reflects key type/size; structure holds for all")
    func headerReflectsKeyTypeAndSize() throws {
        let keyTypes: [(KeyType, String, Int)] = [
            (.ed25519, "ED25519", 256),
            (.ecdsa256, "ECDSA", 256),
            (.ecdsa384, "ECDSA", 384),
            (.ecdsa521, "ECDSA", 521)
        ]
        
        for (keyType, expectedName, expectedSize) in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType)
            let art = RandomArt.generate(for: key)
            
            #expect(art.contains("[\(expectedName) \(expectedSize)]"))
            // Structure checks for each type
            let lines = art.split(separator: "\n")
            #expect(lines.count == 11)
            for i in 1...9 {
                #expect(lines[i].hasPrefix("|"))
                #expect(lines[i].hasSuffix("|"))
                #expect(lines[i].count == 19)
            }
            let field = lines[1...9].joined()
            #expect(field.contains("S"))
            #expect(field.contains("E"))
        }
    }
    
    
}
