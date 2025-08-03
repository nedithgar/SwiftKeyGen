#!/usr/bin/env swift

import Foundation
import Crypto

let hostname = "test.swiftkeygen.example"
let sshKeygenHash = "|1|9lJeWLayTN6JX+REkjwXCryLpxM=|ErZ7D5Wf46EklpyWFhZsW4P9x5o="

// Parse the hash
let components = sshKeygenHash.split(separator: "|").map(String.init)
guard components.count >= 3,
      components[0] == "1",
      let salt = Data(base64Encoded: String(components[1])),
      let expectedHash = Data(base64Encoded: String(components[2])) else {
    print("Failed to parse hash")
    exit(1)
}

print("Hostname: \(hostname)")
print("SSH-Keygen Hash: \(sshKeygenHash)")
print("Salt (hex): \(salt.map { String(format: "%02x", $0) }.joined())")
print("Expected Hash (hex): \(expectedHash.map { String(format: "%02x", $0) }.joined())")

// Compute HMAC with SwiftKeyGen's method
let hostData = Data(hostname.utf8)
let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: hostData, using: SymmetricKey(data: salt))
let computedHash = Data(hmac)

print("Computed Hash (hex): \(computedHash.map { String(format: "%02x", $0) }.joined())")
print("Match: \(computedHash == expectedHash ? "✅ YES" : "❌ NO")")

// Generate the same format hash
let ourHash = "|1|\(salt.base64EncodedString())|\(computedHash.base64EncodedString())"
print("\nOur Hash: \(ourHash)")
print("Identical: \(ourHash == sshKeygenHash ? "✅ YES" : "❌ NO")")