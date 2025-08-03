import Testing
@testable import SwiftKeyGen
import Foundation

@Test("OpenSSL IV format investigation")
func opensslIVTest() throws {
    // Create a temporary file with known content
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let plainFile = tempDir.appendingPathComponent("plain_\(testId).txt").path
    let encFile = tempDir.appendingPathComponent("enc_\(testId).txt").path
    
    let testData = "Hello, OpenSSL!"
    try testData.write(toFile: plainFile, atomically: true, encoding: .utf8)
    
    // Encrypt with OpenSSL using a known salt
    let salt = "0102030405060708" // 8 bytes in hex
    let passphrase = "test123"
    
    // Use OpenSSL to encrypt with specific salt
    let encProcess = Process()
    encProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    encProcess.arguments = [
        "enc",
        "-aes-128-cbc",
        "-in", plainFile,
        "-out", encFile,
        "-pass", "pass:\(passphrase)",
        "-S", salt,  // Specify salt
        "-p"  // Print key/iv
    ]
    
    let outputPipe = Pipe()
    encProcess.standardOutput = outputPipe
    
    try encProcess.run()
    encProcess.waitUntilExit()
    
    let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    print("=== OpenSSL encryption output ===")
    print(output)
    
    // Read the encrypted file and extract DEK-Info
    let encData = try Data(contentsOf: URL(fileURLWithPath: encFile))
    let encString = String(data: encData, encoding: .utf8) ?? ""
    print("\n=== Encrypted file content ===")
    print(encString)
    
    // Now test our implementation with same salt
    let saltData = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    let (key, iv) = PEMEncryption.evpBytesToKey(
        password: passphrase,
        salt: saltData,
        keyLen: 16,
        ivLen: 16
    )
    
    print("\n=== Our key derivation ===")
    print("Salt: \(saltData.hexEncodedString())")
    print("Key:  \(key.hexEncodedString())")
    print("IV:   \(iv.hexEncodedString())")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: plainFile)
    try? FileManager.default.removeItem(atPath: encFile)
}