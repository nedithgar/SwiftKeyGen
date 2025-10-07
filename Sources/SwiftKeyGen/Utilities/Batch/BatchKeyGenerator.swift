import Foundation

/// Configuration for batch key generation.
///
/// Provide this value type to `BatchKeyGenerator` to describe how many keys
/// to create, what algorithm to use, and optional metadata (comments,
/// passphrase, key size). All properties are immutable after initialization
/// which makes the instance safe to share across tasks.
public struct BatchKeyConfiguration {
    /// Key algorithm to generate for each item.
    ///
    /// This value is passed directly through to `SwiftKeyGen.generateKeyPair` and
    /// `KeyFileManager.generateKeyPairFiles`.
    public let keyType: KeyType
    /// Number of keys to generate in the batch.
    ///
    /// Must be non‑negative. No explicit validation is performed here; callers
    /// should ensure sensible limits (e.g. to avoid overwhelming the system).
    public let count: Int
    /// Optional size override for RSA keys only (e.g. 2048, 3072, 4096).
    ///
    /// Ignored for non‑RSA key types.
    public let bits: Int?
    /// Optional base comment. The current index (e.g. `_3`) is appended per
    /// generated key when provided.
    public let baseComment: String?
    /// Base filename used to derive output paths per key.
    ///
    /// Each generated key's private key filename becomes
    /// `"\(baseFilename)_<index>"` and its public key filename adds the
    /// `.pub` suffix.
    public let baseFilename: String
    /// Optional passphrase applied to each generated private key file at rest.
    ///
    /// If `nil`, keys are written unencrypted (consistent with OpenSSH's
    /// default unless the user specifies otherwise).
    public let passphrase: String?
    
    /// Creates a new batch generation configuration.
    ///
    /// - Parameters:
    ///   - keyType: The algorithm to generate for every key in the batch.
    ///   - count: Total number of key pairs to create.
    ///   - bits: Optional RSA modulus size (only used when `keyType == .rsa`).
    ///   - baseComment: A base comment; the index is appended per key if present.
    ///   - baseFilename: Base path/filename stem for output files.
    ///   - passphrase: Optional passphrase used to encrypt each private key file.
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
///
/// A `BatchKeyResult` is produced for every attempted key generation—both
/// successful and failed attempts. When an error occurs, `error` is populated
/// and `fingerprint` is an empty string. Consumers should check `error` first
/// to determine success instead of relying on the fingerprint being empty.
public struct BatchKeyResult {
    /// Index of this key within the batch sequence (zero‑based).
    public let index: Int
    /// Filesystem path of the generated private key (requested destination).
    public let privateKeyPath: String
    /// Filesystem path of the generated public key (private path plus `.pub`).
    public let publicKeyPath: String
    /// The computed fingerprint of the public key (hash algorithm determined
    /// by the underlying `KeyPair.fingerprint()` implementation).
    public let fingerprint: String
    /// An error encountered during generation or file writing; `nil` on
    /// success.
    public let error: Error?
}

/// Utilities to generate many keys and write them to disk.
///
/// `BatchKeyGenerator` provides higher‑level batch flows on top of the core
/// `SwiftKeyGen` + `KeyFileManager` APIs. It intentionally returns per‑item
/// results instead of throwing early so callers can inspect partial progress
/// and surface a consolidated report.
public struct BatchKeyGenerator {
    
    /// Generates multiple keys according to a batch configuration.
    ///
    /// For each index `i` in `0..<configuration.count` a key pair is generated
    /// and written to disk using the derived filename pattern
    /// `"\(configuration.baseFilename)_\(i)"`. Individual failures are captured
    /// in their corresponding `BatchKeyResult` rather than aborting the entire
    /// batch. The `progress` closure, when supplied, is invoked before each
    /// iteration and once at completion with `(completed, total)` counts.
    ///
    /// - Parameters:
    ///   - configuration: The batch parameters controlling algorithm, count and output naming.
    ///   - progress: Optional callback invoked with `(currentIndex, total)`.
    /// - Returns: An ordered array of per‑key results (length equals `count`).
    /// - Throws: Propagates only configuration‑level errors that occur before iteration.
    /// - Note: Per‑key generation errors do not throw; they are recorded in each result's `error`.
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
    
    /// Generates keys for a list of hostnames using a consistent naming scheme.
    ///
    /// Each host receives its own key pair with the filename pattern:
    /// `id_<algorithm>_<host>` inside `outputDirectory` (public key adds `.pub`).
    /// The comment defaults to `root@<host>` mirroring common infrastructure
    /// provisioning patterns. Host failures do not abort the loop—an entry with
    /// an error is stored instead.
    ///
    /// - Parameters:
    ///   - hosts: Collection of hostnames (or identifiers) to generate keys for.
    ///   - keyType: Algorithm to use (default: `.ed25519`).
    ///   - outputDirectory: Directory into which key files are written.
    ///   - passphrase: Optional passphrase to encrypt private keys.
    /// - Returns: Dictionary keyed by host string with its generation result.
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
    
    /// Generates a standard set of key types for a single identity.
    ///
    /// The default set includes: Ed25519, ECDSA P‑256, P‑384, and P‑521. If
    /// `includeRSA` is true, an RSA key of `rsaBits` size is also produced.
    /// Output filenames follow the OpenSSH `id_<algorithm>` pattern (e.g.
    /// `id_ed25519`, `id_ecdsa256`, `id_rsa`). Individual failures are captured
    /// without aborting the rest of the generation.
    ///
    /// - Parameters:
    ///   - identity: Comment to embed in each public key (e.g. `user@host`).
    ///   - outputDirectory: Directory where key files are written.
    ///   - includeRSA: Whether to include an RSA key (default true).
    ///   - rsaBits: RSA modulus size when `includeRSA` is true (default 3072).
    /// - Returns: Dictionary mapping each `KeyType` to its result.
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
