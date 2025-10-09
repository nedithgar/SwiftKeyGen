import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("OpenSSHPublicKeyParser Unit Tests", .tags(.unit))
struct OpenSSHPublicKeyParserUnitTests {

    // MARK: - Detection

    @Test("detectKeyType returns expected type for each non-RSA algorithm")
    func testDetectKeyTypeNonRSA() throws {
        // Exclude RSA to keep this fast (RSA generation is slower)
        for keyType in [KeyType.ed25519, .ecdsa256, .ecdsa384, .ecdsa521] {
            let key = try SwiftKeyGen.generateKey(type: keyType, comment: "det")
            let publicKey = key.publicKeyString()
            let detected = OpenSSHPublicKeyParser.detectKeyType(from: publicKey)
            #expect(detected == keyType, "Expected to detect \(keyType) from \(publicKey)")
        }
    }

    @Test("detectKeyType handles malformed input gracefully (nil)")
    func testDetectKeyTypeMalformed() {
        let inputs = ["", "ssh-ed25519", "onlytwo ", "missingb64 comment"]
        for input in inputs {
            #expect(OpenSSHPublicKeyParser.detectKeyType(from: input) == nil)
        }
    }

    // MARK: - Parse Success Paths

    @Test("parse extracts comment when present")
    func testParseWithComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@host") as! Ed25519Key
        let line = key.publicKeyString()
        let (t, data, comment) = try OpenSSHPublicKeyParser.parse(line)
        #expect(t == .ed25519)
        #expect(data == key.publicKeyData())
        #expect(comment == "user@host")
    }

    @Test("parse handles absence of comment")
    func testParseWithoutComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let line = key.publicKeyString() // generator omits comment when none provided
        let (t, _, comment) = try OpenSSHPublicKeyParser.parse(line)
        #expect(t == .ed25519)
        #expect(comment == nil)
    }

    // MARK: - Error Cases

    @Test("parse invalid base64 -> invalidKeyData")
    func testParseInvalidBase64() {
        let line = "ssh-ed25519 !!!notbase64!!! comment"
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try OpenSSHPublicKeyParser.parse(line)
        }
    }

    @Test("parse unsupported key type -> unsupportedKeyType")
    func testParseUnsupportedKeyType() {
        // Provide a trivially valid base64 that decodes to empty -> will fail validation AFTER unsupported type is detected
        let line = "ssh-unknown AAAA comment" // 'AAAA' -> 0x00 0x00 0x00 0x00 (length 0) which is fine for triggering unsupported case first
        #expect(throws: SSHKeyError.unsupportedKeyType) {
            _ = try OpenSSHPublicKeyParser.parse(line)
        }
    }

    @Test("parse with insufficient components -> invalidKeyData")
    func testParseInsufficientComponents() {
        let line = "ssh-ed25519" // Missing base64 portion entirely
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try OpenSSHPublicKeyParser.parse(line)
        }
    }

    @Test("parse with structurally invalid decoded blob -> invalidKeyData")
    func testParseStructurallyInvalidBlob() {
        // Build an ed25519 line with a truncated SSH wire blob.
        // Normal structure: string(type) + string(pubkey32). We'll encode only the type length header without full data.
        var enc = Data()
        // length (UInt32) for type = 11 ("ssh-ed25519")
        enc.append(contentsOf: [0,0,0,11])
        enc.append(Data("ssh-ed25519".utf8))
        // Intentionally omit the following public key data field => validatePublicKeyData should throw
        let b64 = enc.base64EncodedString()
        let line = "ssh-ed25519 \(b64) truncated@test"
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try OpenSSHPublicKeyParser.parse(line)
        }
    }
}
