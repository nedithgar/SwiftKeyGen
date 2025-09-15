import Foundation

/// Configuration for batch key generation.
public struct BatchKeyConfiguration {
    /// Key algorithm to generate for each item.
    public let keyType: KeyType
    /// Number of keys to generate.
    public let count: Int
    /// Optional size override (RSA only).
    public let bits: Int?
    /// Optional base comment (index is appended per key).
    public let baseComment: String?
    /// Base filename used to derive outputs per key.
    public let baseFilename: String
    /// Optional passphrase applied to private keys at rest.
    public let passphrase: String?
    
    public init(
        keyType: KeyType,
        count: Int,
        bits: Int? = nil,
        baseComment: String? = nil,
        baseFilename: String,
        passphrase: String? = nil
    ) {
        self.keyType = keyType
        self.count = count
        self.bits = bits
        self.baseComment = baseComment
        self.baseFilename = baseFilename
        self.passphrase = passphrase
    }
}

/// Result for a single generated key in a batch.
public struct BatchKeyResult {
    public let index: Int
    public let privateKeyPath: String
    public let publicKeyPath: String
    public let fingerprint: String
    public let error: Error?
}

/// Utilities to generate many keys and write them to disk.
public struct BatchKeyGenerator {
    
    /// Generate multiple keys in batch.
    public static func generateBatch(
        configuration: BatchKeyConfiguration,
        progress: ((Int, Int) -> Void)? = nil
    ) async throws -> [BatchKeyResult] {
        var results: [BatchKeyResult] = []
        
        for i in 0..<configuration.count {
            progress?(i, configuration.count)
            
            let filename = "\(configuration.baseFilename)_\(i)"
            let comment = configuration.baseComment.map { "\($0)_\(i)" }
            
            do {
                let keyPair = try SwiftKeyGen.generateKeyPair(
                    type: configuration.keyType,
                    bits: configuration.bits,
                    comment: comment
                )
                
                try KeyFileManager.generateKeyPairFiles(
                    type: configuration.keyType,
                    privatePath: filename,
                    bits: configuration.bits,
                    comment: comment,
                    passphrase: configuration.passphrase
                )
                
                let result = BatchKeyResult(
                    index: i,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: keyPair.fingerprint(),
                    error: nil
                )
                
                results.append(result)
            } catch {
                let result = BatchKeyResult(
                    index: i,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: "",
                    error: error
                )
                results.append(result)
            }
        }
        
        progress?(configuration.count, configuration.count)
        return results
    }
    
    /// Generate keys for multiple hosts.
    public static func generateForHosts(
        hosts: [String],
        keyType: KeyType = .ed25519,
        outputDirectory: String,
        passphrase: String? = nil
    ) async throws -> [String: BatchKeyResult] {
        var results: [String: BatchKeyResult] = [:]
        
        for (index, host) in hosts.enumerated() {
            let filename = URL(fileURLWithPath: outputDirectory)
                .appendingPathComponent("id_\(keyType.algorithmName.lowercased())_\(host)")
                .path
            
            do {
                let keyPair = try SwiftKeyGen.generateKeyPair(
                    type: keyType,
                    comment: "root@\(host)"
                )
                
                try KeyFileManager.generateKeyPairFiles(
                    type: keyType,
                    privatePath: filename,
                    comment: "root@\(host)",
                    passphrase: passphrase
                )
                
                let result = BatchKeyResult(
                    index: index,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: keyPair.fingerprint(),
                    error: nil
                )
                
                results[host] = result
            } catch {
                let result = BatchKeyResult(
                    index: index,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: "",
                    error: error
                )
                results[host] = result
            }
        }
        
        return results
    }
    
    /// Generate multiple key types for a single identity.
    public static func generateAllTypes(
        identity: String,
        outputDirectory: String,
        includeRSA: Bool = true,
        rsaBits: Int = 3072
    ) async throws -> [KeyType: BatchKeyResult] {
        var results: [KeyType: BatchKeyResult] = [:]
        
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]
        
        for (index, keyType) in keyTypes.enumerated() {
            let filename = URL(fileURLWithPath: outputDirectory)
                .appendingPathComponent("id_\(keyType.algorithmName.lowercased())")
                .path
            
            do {
                try KeyFileManager.generateKeyPairFiles(
                    type: keyType,
                    privatePath: filename,
                    comment: identity
                )
                
                let keyPair = try SwiftKeyGen.generateKeyPair(
                    type: keyType,
                    comment: identity
                )
                
                let result = BatchKeyResult(
                    index: index,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: keyPair.fingerprint(),
                    error: nil
                )
                
                results[keyType] = result
            } catch {
                let result = BatchKeyResult(
                    index: index,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: "",
                    error: error
                )
                results[keyType] = result
            }
        }
        
        // Generate RSA if requested
        if includeRSA {
            let filename = URL(fileURLWithPath: outputDirectory)
                .appendingPathComponent("id_rsa")
                .path
            
            do {
                try KeyFileManager.generateKeyPairFiles(
                    type: .rsa,
                    privatePath: filename,
                    bits: rsaBits,
                    comment: identity
                )
                
                let keyPair = try SwiftKeyGen.generateKeyPair(
                    type: .rsa,
                    bits: rsaBits,
                    comment: identity
                )
                
                let result = BatchKeyResult(
                    index: keyTypes.count,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: keyPair.fingerprint(),
                    error: nil
                )
                
                results[.rsa] = result
            } catch {
                let result = BatchKeyResult(
                    index: keyTypes.count,
                    privateKeyPath: filename,
                    publicKeyPath: filename + ".pub",
                    fingerprint: "",
                    error: error
                )
                results[.rsa] = result
            }
        }
        
        return results
    }
}
