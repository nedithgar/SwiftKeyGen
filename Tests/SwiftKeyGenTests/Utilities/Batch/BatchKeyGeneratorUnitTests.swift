import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("BatchKeyGenerator Unit Tests", .tags(.unit))
struct BatchKeyGeneratorUnitTests {

    // MARK: - Helpers
    private func tempDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("batch-keygen-tests-\(UUID().uuidString)")
    }

    private func listFiles(at url: URL) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
    }

    @Test("generateBatch creates expected number of key pairs, filenames, comments, fingerprints non-empty")
    func testGenerateBatchBasic() async throws {
        let dir = tempDirectory()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let config = BatchKeyConfiguration(
            keyType: .ed25519,
            count: 3,
            baseComment: "batch@test",
            baseFilename: dir.appendingPathComponent("id_batch").path,
            passphrase: nil
        )

        var progressEvents: [(Int, Int)] = []
        let results = try await BatchKeyGenerator.generateBatch(configuration: config) { cur, total in
            progressEvents.append((cur, total))
        }

        #expect(results.count == 3)
        for (i, r) in results.enumerated() {
            #expect(r.index == i)
            #expect(r.privateKeyPath.hasSuffix("id_batch_\(i)"))
            #expect(r.publicKeyPath == r.privateKeyPath + ".pub")
            #expect(r.error == nil)
            #expect(!r.fingerprint.isEmpty)
            // File existence
            #expect(FileManager.default.fileExists(atPath: r.privateKeyPath))
            #expect(FileManager.default.fileExists(atPath: r.publicKeyPath))
            // Public key contains comment with suffixed index
            let pub = try String(contentsOf: URL(fileURLWithPath: r.publicKeyPath), encoding: .utf8)
            #expect(pub.contains("batch@test_\(i)"))
        }

        // Progress should include an entry for each index plus final completion
        #expect(progressEvents.contains { $0.0 == 0 && $0.1 == 3 })
        #expect(progressEvents.contains { $0.0 == 1 && $0.1 == 3 })
        #expect(progressEvents.contains { $0.0 == 2 && $0.1 == 3 })
        if let last = progressEvents.last {
            #expect(last.0 == 3 && last.1 == 3)
        } else {
            #expect(Bool(false), "Expected completion progress event (3,3)")
        }
    }

    @Test("generateBatch count 0 yields empty results and still fires completion progress")
    func testGenerateBatchZero() async throws {
        let dir = tempDirectory(); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let config = BatchKeyConfiguration(keyType: .ed25519, count: 0, baseFilename: dir.appendingPathComponent("id_empty").path)
        var progressEvents: [(Int, Int)] = []
        let results = try await BatchKeyGenerator.generateBatch(configuration: config) { cur, total in
            progressEvents.append((cur, total))
        }
        #expect(results.isEmpty)
        // Only completion event expected: (0,0)
        #expect(progressEvents.count == 1)
        #expect(progressEvents.first?.0 == 0 && progressEvents.first?.1 == 0)
    }

    @Test("generateForHosts produces per-host files with root@host comments")
    func testGenerateForHosts() async throws {
        let dir = tempDirectory(); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let hosts = ["alpha", "beta", "gamma"]
        let results = try await BatchKeyGenerator.generateForHosts(hosts: hosts, keyType: .ed25519, outputDirectory: dir.path)
        #expect(results.count == hosts.count)
        for (idx, host) in hosts.enumerated() {
            guard let r = results[host] else { #expect(Bool(false)); continue }
            #expect(r.index == idx)
            #expect(r.error == nil)
            let pub = try String(contentsOf: URL(fileURLWithPath: r.publicKeyPath), encoding: .utf8)
            #expect(pub.contains("root@\(host)"))
            #expect(!r.fingerprint.isEmpty)
        }
    }

    @Test("generateAllTypes produces expected key set (w/o RSA)")
    func testGenerateAllTypesNoRSA() async throws {
        let dir = tempDirectory(); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let results = try await BatchKeyGenerator.generateAllTypes(identity: "user@test", outputDirectory: dir.path, includeRSA: false)
        let expected: Set<KeyType> = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]
        #expect(Set(results.keys) == expected)
        for (kt, r) in results {
            #expect(r.error == nil)
            #expect(!r.fingerprint.isEmpty)
            #expect(FileManager.default.fileExists(atPath: r.privateKeyPath))
            #expect(FileManager.default.fileExists(atPath: r.publicKeyPath))
            let pub = try String(contentsOf: URL(fileURLWithPath: r.publicKeyPath), encoding: .utf8)
            #expect(pub.contains("user@test"))
            // Public key line should start with the OpenSSH algorithm identifier (lowercased format)
            #expect(pub.lowercased().hasPrefix(kt.algorithmName.lowercased().replacingOccurrences(of: "ecdsa", with: "ecdsa-sha2")) || pub.lowercased().hasPrefix(kt.algorithmName.lowercased()) || kt == .ed25519)
        }
    }

    @Test("generateAllTypes includes RSA when requested", .tags(.rsa))
    func testGenerateAllTypesWithRSA() async throws {
        let dir = tempDirectory(); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let results = try await BatchKeyGenerator.generateAllTypes(identity: "user@test", outputDirectory: dir.path, includeRSA: true, rsaBits: 2048)
        let expected: Set<KeyType> = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521, .rsa]
        #expect(Set(results.keys) == expected)
        #expect(results[.rsa]?.fingerprint.isEmpty == false)
    }

    @Test("generateBatch propagates per-item failure without aborting")
    func testGenerateBatchFailureIsolation() async throws {
        // We simulate a failure by attempting to write into a directory path as a file (common permission / isDirectory error).
        // Create a directory named as the private key target for index 1 so that write fails when trying to overwrite.
        let baseDir = tempDirectory(); try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: baseDir) }
        let failingPath = baseDir.appendingPathComponent("id_batch_1").path
        try FileManager.default.createDirectory(atPath: failingPath, withIntermediateDirectories: true)
        let config = BatchKeyConfiguration(keyType: .ed25519, count: 3, baseComment: "fail@test", baseFilename: baseDir.appendingPathComponent("id_batch").path)
        let results = try await BatchKeyGenerator.generateBatch(configuration: config)
        #expect(results.count == 3)
        // Index 1 should carry an error, others succeed.
        for r in results {
            if r.index == 1 { #expect(r.error != nil); #expect(r.fingerprint.isEmpty) } else { #expect(r.error == nil); #expect(!r.fingerprint.isEmpty) }
        }
    }
}
