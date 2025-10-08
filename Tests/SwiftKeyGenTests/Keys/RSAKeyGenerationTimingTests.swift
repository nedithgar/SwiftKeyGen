import Foundation
import Testing
@testable import SwiftKeyGen

@Suite("RSA Key Generation Timing", .tags(.slow, .rsa))
struct RSAKeyGenerationTimingTests {

    /// Simple one-off timing of 2048-bit RSA key generation inside SwiftKeyGen.
    /// External `ssh-keygen` comparison was removed after initial investigation;
    /// this now serves only as a lightweight canary to record duration and
    /// ensure generation still succeeds.
    @Test("Generate single 2048-bit RSA key (timing only)")
    func generateSingleRSA2048Timing() throws {
        let start = CFAbsoluteTimeGetCurrent()
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
    let duration = CFAbsoluteTimeGetCurrent() - start
    _ = duration // silence unused variable warning; uncomment Issue.record if needed

        // Sanity checks (keep minimal to avoid extra overhead)
        #expect(key.keyType == .rsa)
        #expect(key.publicKeyData().count > 0)

        // Issue.record("SwiftKeyGen RSA 2048 generation duration: \(String(format: "%.4f", duration)) s")
    }
}
