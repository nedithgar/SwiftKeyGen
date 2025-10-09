// DEPRECATED: This file has been superseded by consolidated tests in
// `Tests/SwiftKeyGenTests/Formats/Common/PublicKeyParserFormatUnitTests.swift` and
// `PublicKeyParserRSAUnitTests`. It remains temporarily to preserve history but
// intentionally contains no executable tests. Remove once migration is validated.

import Testing
@testable import SwiftKeyGen

@Suite("PublicKeyParser Legacy Placeholder", .tags(.unit))
struct PublicKeyParserLegacyPlaceholderTests {
    @Test func placeholder() throws {
        // Intentionally empty – see consolidated suites.
        #expect(true)
    }
}
