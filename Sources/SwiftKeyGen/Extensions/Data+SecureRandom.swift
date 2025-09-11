// import Foundation
// import Security

// /// Secure random byte generation helpers for Data
// /// Centralizes use of SecRandomCopyBytes and avoids duplication.
// extension Data {
//     /// Generate a Data buffer filled with cryptographically secure random bytes.
//     /// - Parameter count: Number of random bytes to generate.
//     /// - Returns: Data containing `count` secure random bytes.
//     /// - Throws: `SSHKeyError.randomGenerationFailed` when the system RNG fails.
//     static func generateSecureRandomBytes(count: Int) throws -> Data {
//         guard count > 0 else { return Data() }
//         var data = Data(count: count)
//         try data.fillWithSecureRandomBytes()
//         return data
//     }

//     /// Fill this Data buffer with cryptographically secure random bytes.
//     /// - Throws: `SSHKeyError.randomGenerationFailed` when the system RNG fails.
//     mutating func fillWithSecureRandomBytes() throws {
//         if self.count == 0 { return }
//         let result = self.withUnsafeMutableBytes { bytes -> Int32 in
//             guard let baseAddress = bytes.baseAddress else { return errSecAllocate }
//             return SecRandomCopyBytes(kSecRandomDefault, bytes.count, baseAddress)
//         }
//         guard result == errSecSuccess else {
//             throw SSHKeyError.randomGenerationFailed
//         }
//     }
// }
