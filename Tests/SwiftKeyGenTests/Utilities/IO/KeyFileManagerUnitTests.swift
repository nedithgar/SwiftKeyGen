import Testing
import Foundation
@testable import SwiftKeyGen

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@Suite("KeyFileManager Unit Tests", .tags(.unit))
struct KeyFileManagerUnitTests {

    // MARK: - FD Capture Helpers
    // Capture stdout produced inside `body` and return it as Data.
    private func captureStdout(_ body: () throws -> Void) throws -> Data {
        let pipeFds = UnsafeMutablePointer<Int32>.allocate(capacity: 2)
        defer { pipeFds.deallocate() }
        #if os(Windows)
        // Windows path not required for this project (POSIX focus); fallback
        try body()
        return Data()
        #else
        if pipe(pipeFds) != 0 { fatalError("pipe failed") }
        let readFd = pipeFds[0]
        let writeFd = pipeFds[1]
        let originalStdout = dup(STDOUT_FILENO)
        if originalStdout == -1 { fatalError("dup stdout failed") }
        if dup2(writeFd, STDOUT_FILENO) == -1 { fatalError("dup2 stdout failed") }
        // Execute body while stdout redirected
        try body()
        // Close writer so reader sees EOF
        close(writeFd)
        // Restore stdout
        fflush(stdout)
        if dup2(originalStdout, STDOUT_FILENO) == -1 { fatalError("restore stdout failed") }
        close(originalStdout)
        // Read captured data
        var buffer = [UInt8]()
        let chunkSize = 4096
        var temp = [UInt8](repeating: 0, count: chunkSize)
        while true {
            let n = read(readFd, &temp, chunkSize)
            if n <= 0 { break }
            buffer.append(contentsOf: temp[0..<n])
        }
        close(readFd)
        return Data(buffer)
        #endif
    }

    // Execute body with provided data served via stdin ("-") sentinel paths.
    private func withStdinData<T>(_ data: Data, _ body: () throws -> T) throws -> T {
        #if os(Windows)
        return try body()
        #else
        let pipeFds = UnsafeMutablePointer<Int32>.allocate(capacity: 2)
        defer { pipeFds.deallocate() }
        if pipe(pipeFds) != 0 { fatalError("pipe failed") }
        let readFd = pipeFds[0]
        let writeFd = pipeFds[1]
        // Write all data then close writer so reader sees EOF immediately
        data.withUnsafeBytes { ptr in
            _ = write(writeFd, ptr.baseAddress, ptr.count)
        }
        close(writeFd)
        let originalStdin = dup(STDIN_FILENO)
        if originalStdin == -1 { fatalError("dup stdin failed") }
        if dup2(readFd, STDIN_FILENO) == -1 { fatalError("dup2 stdin failed") }
        defer {
            fflush(stdin)
            if dup2(originalStdin, STDIN_FILENO) == -1 { fatalError("restore stdin failed") }
            close(originalStdin)
            close(readFd)
        }
        return try body()
        #endif
    }

    // MARK: - Tests

    @Test("writeKey public -> stdout adds trailing newline and format")
    func testWritePublicKeyToStdout() throws {
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "stdout@test")
        let captured = try captureStdout {
            try KeyFileManager.writeKey(pair, to: KeyFileManager.STDIN_STDOUT_FILENAME, type: .publicKey)
        }
        let text = String(data: captured, encoding: .utf8) ?? ""
        #expect(text.hasPrefix("ssh-ed25519 "))
        #expect(text.contains("stdout@test"))
        #expect(text.hasSuffix("\n")) // newline added for shell friendliness
    }

    @Test("writeKey private -> stdout emits OpenSSH PEM block")
    func testWritePrivateKeyToStdout() throws {
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "priv@test")
        let captured = try captureStdout {
            try KeyFileManager.writeKey(pair, to: KeyFileManager.STDIN_STDOUT_FILENAME, type: .privateKey)
        }
        let pem = String(data: captured, encoding: .utf8) ?? ""
        #expect(pem.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        #expect(pem.contains("-----END OPENSSH PRIVATE KEY-----"))
    }

    @Test("writeDataToStdout + writeStringToStdout concatenation")
    func testDirectStdoutHelpers() throws {
        let dataPart = Data([0x41, 0x42, 0x43]) // ABC
        let stringPart = "XYZ"
        let captured = try captureStdout {
            KeyFileManager.writeDataToStdout(dataPart)
            KeyFileManager.writeStringToStdout(stringPart)
        }
        let text = String(data: captured, encoding: .utf8) ?? ""
        #expect(text == "ABCXYZ")
    }

    @Test("readKeyData from file vs '-' stdin sentinel")
    func testReadKeyDataFileAndStdin() throws {
        let tmpDir = FileManager.default.temporaryDirectory
        let fileURL = tmpDir.appendingPathComponent("keyfilemanager-stdin-test-")
        let bytes = Data("sample stdin data".utf8)
        try bytes.write(to: fileURL)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        // From file path
        let fromFile = try KeyFileManager.readKeyData(from: fileURL.path)
        #expect(fromFile == bytes)

        // From stdin sentinel
        let fromStdin = try withStdinData(bytes) {
            try KeyFileManager.readKeyData(from: KeyFileManager.STDIN_STDOUT_FILENAME)
        }
        #expect(fromStdin == bytes)
    }

    @Test("generateKeyPairFiles with passphrase -> encrypted parse behaviors")
    func testGenerateEncryptedKeyPairFiles() throws {
        let tmpDir = FileManager.default.temporaryDirectory
        let privPath = tmpDir.appendingPathComponent("enc_ed25519_test").path
        let pubPath = privPath + ".pub"
        try? FileManager.default.removeItem(atPath: privPath)
        try? FileManager.default.removeItem(atPath: pubPath)
        defer {
            try? FileManager.default.removeItem(atPath: privPath)
            try? FileManager.default.removeItem(atPath: pubPath)
        }

        let passphrase = "unit-passphrase"
        try KeyFileManager.generateKeyPairFiles(
            type: .ed25519,
            privatePath: privPath,
            publicPath: nil,
            bits: nil,
            comment: "enc@test",
            passphrase: passphrase
        )

        // Files created
        #expect(FileManager.default.fileExists(atPath: privPath))
        #expect(FileManager.default.fileExists(atPath: pubPath))

        let privData = try Data(contentsOf: URL(fileURLWithPath: privPath))
        // Attempt parse without passphrase -> should throw .passphraseRequired
        var threwRequired = false
        do { _ = try OpenSSHPrivateKey.parse(data: privData) } catch let err as SSHKeyError {
            threwRequired = (err == .passphraseRequired)
        } catch { }
        #expect(threwRequired)

        // Parse with passphrase succeeds
        let parsed = try OpenSSHPrivateKey.parse(data: privData, passphrase: passphrase)
        #expect(parsed.keyType == .ed25519)
    }
}
