import Foundation
import BigInt
import Crypto

// MARK: - Insecure RSA Implementation

extension Insecure {
    /// Namespace that provides an (intentionally) insecure / minimal RSA implementation.
    ///
    /// This type exists for:
    ///  - Format / interoperability tests (e.g. ASN.1 / DER parsing, OpenSSH conversion)
    ///  - Educational inspection of the raw mathematics behind higher‑level APIs
    ///  - Fallback / legacy behaviors where a fully hardened implementation is not required
    ///
    /// It is **NOT** a complete, constant‑time, side‑channel resistant implementation and
    /// must not be used for production security boundaries. Prefer the hardened key types
    /// exposed elsewhere in the library (e.g. `RSAKey`) for real cryptographic operations.
    ///
    /// - Warning: This module purposefully omits a variety of mitigations (blinding, padding
    ///   oracle protections, strict ASN.1 validation hardening, fault attack countermeasures).
    ///   Do not expose these primitives directly to untrusted inputs outside of controlled tests.
    public enum RSA {
        
        // MARK: - Key Generation
        
        /// Generates a new RSA key pair.
        ///
        /// Prime generation uses a probabilistic Miller–Rabin test; keys are retried until
        /// the modulus reaches the requested bit length and the modular inverse for `e`
        /// exists. Uses public exponent 65537.
        ///
        /// - Parameter bitSize: Desired bit size of the RSA modulus (must be ≥ 512 and a multiple of 8). Defaults to 2048.
        /// - Returns: A tuple containing the newly created `PrivateKey` and matching `PublicKey`.
        /// - Throws: `SSHKeyError.invalidKeySize` when the supplied size is unsupported, or
        ///   `SSHKeyError.generationFailed` if a valid key could not be produced after repeated attempts.
        /// - Important: This function is for testing / compatibility only and does not attempt to
        ///   enforce modern minimum sizes or policies. Callers are responsible for validating strength.
        public static func generateKeyPair(bitSize: Int = 2048) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
            guard bitSize >= 512 && bitSize % 8 == 0 else {
                throw SSHKeyError.invalidKeySize(bitSize, "RSA key size must be at least 512 bits and a multiple of 8")
            }
            
            // Public exponent (fixed)
            let e = BigUInt(65537)

            // Generate primes separately ensuring gcd(e, p-1) == 1 before moving on.
            let halfBits = bitSize / 2
            let p = try generatePrime(bitSize: halfBits, ensureCoprimeWith: e)
            var q: BigUInt
            repeat {
                q = try generatePrime(bitSize: halfBits, ensureCoprimeWith: e)
            } while q == p // extremely unlikely, but guard uniqueness

            // With top two bits forced for at least one prime the modulus will have full bitSize.
            let n = p * q
            // Sanity: guarantee we achieved requested size (should always hold with top-two-bit technique)
            if n.bitWidth < bitSize {
                // Fallback: regenerate q once (very rare) then recompute
                q = try generatePrime(bitSize: halfBits, ensureCoprimeWith: e)
                let n2 = p * q
                guard n2.bitWidth >= bitSize else {
                    throw SSHKeyError.generationFailed("Failed to reach target bit size for modulus")
                }
                return try finalizeKey(e: e, p: p, q: q, n: n2)
            }
            return try finalizeKey(e: e, p: p, q: q, n: n)
        }
        
        /// Finalize key components computing d and constructing key types.
        private static func finalizeKey(e: BigUInt, p: BigUInt, q: BigUInt, n: BigUInt) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
            let phi = (p - 1) * (q - 1)
            guard let d = modularInverse(e, phi) else {
                throw SSHKeyError.generationFailed("Could not invert e modulo phi(n)")
            }
            let publicKey = PublicKey(n: n, e: e)
            let privateKey = PrivateKey(n: n, e: e, d: d, p: p, q: q)
            return (privateKey, publicKey)
        }
        
        // MARK: - Key Types
        
        /// Public portion of an RSA key pair.
        ///
        /// Encapsulates the modulus `n` and public exponent `e`. Utility accessors are provided
        /// for serialization and size queries.
        public struct PublicKey {
            /// The RSA modulus (n).
            public let n: BigUInt  // modulus
            /// The public exponent (e). Commonly 65537.
            public let e: BigUInt  // public exponent
            
            /// Creates a new public key from raw big integer components.
            /// - Parameters:
            ///   - n: The modulus.
            ///   - e: The public exponent.
            public init(n: BigUInt, e: BigUInt) {
                self.n = n
                self.e = e
            }
            
            /// Initializes a public key from serialized big‑endian data blobs.
            ///
            /// - Parameters:
            ///   - modulus: Big‑endian representation of the modulus.
            ///   - exponent: Big‑endian representation of the exponent.
            /// - Throws: Never directly, but kept `throws` to align with potential future validation additions.
            public init(modulus: Data, exponent: Data) throws {
                self.n = BigUInt(modulus)
                self.e = BigUInt(exponent)
            }
            
            /// The modulus serialized as big‑endian bytes.
            public var modulusData: Data {
                return n.serialize()
            }
            
            /// The public exponent serialized as big‑endian bytes.
            public var exponentData: Data {
                return e.serialize()
            }
            
            /// Effective RSA modulus size in bits.
            public var bitSize: Int {
                return n.bitWidth
            }
        }
        
        /// Private portion of an RSA key pair including CRT optimization values.
        ///
        /// All key constituents (`p`, `q`, `d`, CRT pre‑computations) are exposed for
        /// interoperability and testing. Treat these values as sensitive material.
        public struct PrivateKey {
            /// Modulus shared with the public key.
            public let n: BigUInt   // modulus
            /// Public exponent.
            public let e: BigUInt   // public exponent
            /// Private exponent (d).
            public let d: BigUInt   // private exponent
            /// First prime factor (p).
            public let p: BigUInt   // prime p
            /// Second prime factor (q).
            public let q: BigUInt   // prime q
            
            // Chinese Remainder Theorem optimization values
            /// d (mod p−1)
            public let dP: BigUInt  // d mod (p-1)
            /// d (mod q−1)
            public let dQ: BigUInt  // d mod (q-1)
            /// Multiplicative inverse of q modulo p.
            public let qInv: BigUInt // q^(-1) mod p
            
            /// Creates a private key and derives CRT parameters automatically.
            /// - Parameters:
            ///   - n: Modulus.
            ///   - e: Public exponent.
            ///   - d: Private exponent.
            ///   - p: First prime.
            ///   - q: Second prime.
            public init(n: BigUInt, e: BigUInt, d: BigUInt, p: BigUInt, q: BigUInt) {
                self.n = n
                self.e = e
                self.d = d
                self.p = p
                self.q = q
                
                // Calculate CRT values
                self.dP = d % (p - 1)
                self.dQ = d % (q - 1)
                self.qInv = modularInverse(q, p) ?? BigUInt(0)
            }
            
            /// Creates a private key with pre‑computed CRT fields (used when importing existing keys).
            /// - Parameters:
            ///   - n: Modulus.
            ///   - e: Public exponent.
            ///   - d: Private exponent.
            ///   - p: First prime.
            ///   - q: Second prime.
            ///   - dP: d (mod p−1).
            ///   - dQ: d (mod q−1).
            ///   - qInv: q⁻¹ (mod p).
            public init(n: BigUInt, e: BigUInt, d: BigUInt, p: BigUInt, q: BigUInt, dP: BigUInt, dQ: BigUInt, qInv: BigUInt) {
                self.n = n
                self.e = e
                self.d = d
                self.p = p
                self.q = q
                self.dP = dP
                self.dQ = dQ
                self.qInv = qInv
            }
            
            /// Extracts the corresponding public key.
            public var publicKey: PublicKey {
                return PublicKey(n: n, e: e)
            }
            
            /// Effective RSA modulus size in bits.
            public var bitSize: Int {
                return n.bitWidth
            }
        }
        
        // MARK: - Encryption/Decryption
        
        /// Encrypts data using PKCS#1 v1.5 padding and the supplied public key.
        ///
        /// - Note: PKCS#1 v1.5 padding is susceptible to padding oracle attacks when
        ///   decryption errors are distinguishable. Use OAEP in production contexts.
        /// - Parameters:
        ///   - plaintext: Message bytes to encrypt.
        ///   - publicKey: Target RSA public key.
        /// - Returns: Ciphertext of size equal to the key modulus length in bytes.
        /// - Throws: `SSHKeyError.invalidKeyData` if the message is too large for the modulus minus padding overhead.
        public static func encrypt(_ plaintext: Data, with publicKey: PublicKey) throws -> Data {
            let keyByteSize = (publicKey.bitSize + 7) / 8
            
            // PKCS#1 v1.5 padding limits message size
            guard plaintext.count <= keyByteSize - 11 else {
                throw SSHKeyError.invalidKeyData
            }
            
            // Apply PKCS#1 v1.5 padding
            let paddedMessage = try pkcs1v15Pad(plaintext, keyByteSize: keyByteSize, forEncryption: true)
            
            // Convert to BigUInt and encrypt: c = m^e mod n
            let m = BigUInt(paddedMessage)
            let c = m.power(publicKey.e, modulus: publicKey.n)
            
            // Convert back to Data with proper size
            return c.serialize().leftPadded(to: keyByteSize)
        }
        
        /// Decrypts data that was produced by `encrypt(_:with:)` (PKCS#1 v1.5).
        ///
        /// - Parameters:
        ///   - ciphertext: Ciphertext bytes whose length must match the key size in bytes.
        ///   - privateKey: The matching RSA private key.
        /// - Returns: The original plaintext message after padding removal.
        /// - Throws: `SSHKeyError.invalidKeyData` if input size is invalid or padding checks fail.
        /// - Warning: Timing differences during padding validation are not masked.
        public static func decrypt(_ ciphertext: Data, with privateKey: PrivateKey) throws -> Data {
            let keyByteSize = (privateKey.bitSize + 7) / 8
            
            guard ciphertext.count == keyByteSize else {
                throw SSHKeyError.invalidKeyData
            }
            
            // Convert to BigUInt
            let c = BigUInt(ciphertext)
            
            // Decrypt using CRT optimization: m = c^d mod n
            let m = decryptWithCRT(c, privateKey: privateKey)
            
            // Convert to Data and remove padding
            let paddedMessage = m.serialize().leftPadded(to: keyByteSize)
            return try pkcs1v15Unpad(paddedMessage, forEncryption: true)
        }
        
        // MARK: - Signing/Verification
        
        /// Produces a PKCS#1 v1.5 signature over `message` using the specified hash algorithm.
        ///
        /// The DigestInfo wrapper (hash OID + digest) is padded per PKCS#1 v1.5 and then exponentiated.
        ///
        /// - Parameters:
        ///   - message: Data to be signed.
        ///   - privateKey: RSA private key.
        ///   - hashAlgorithm: Hash function (default `.sha256`).
        /// - Returns: Raw signature bytes whose length equals the key modulus length in bytes.
        /// - Throws: `SSHKeyError.invalidKeyData` if padding fails (extremely unlikely under normal sizes).
        /// - Important: PKCS#1 v1.5 signatures are vulnerable to certain subtle attacks if verification
        ///   is non‑strict. Verification here is intentionally narrow but not fully hardened.
        public static func sign(_ message: Data, with privateKey: PrivateKey, hashAlgorithm: HashAlgorithm = .sha256) throws -> Data {
            let keyByteSize = (privateKey.bitSize + 7) / 8
            
            // Calculate hash based on algorithm
            let hash: Data
            switch hashAlgorithm {
            case .sha1:
                hash = message.sha1DataInsecure()
            case .sha256:
                hash = message.sha256Data()
            case .sha384:
                hash = message.sha384Data()
            case .sha512:
                hash = message.sha512Data()
            }
            
            // Create DigestInfo structure
            let digestInfo = createDigestInfo(hash: hash, algorithm: hashAlgorithm)
            
            // Apply PKCS#1 v1.5 padding for signing
            let paddedMessage = try pkcs1v15Pad(digestInfo, keyByteSize: keyByteSize, forEncryption: false)
            
            // Sign: s = m^d mod n
            let m = BigUInt(paddedMessage)
            let s = decryptWithCRT(m, privateKey: privateKey)
            
            return s.serialize().leftPadded(to: keyByteSize)
        }
        
        /// Convenience overload that signs using SHA‑256.
        ///
        /// - Parameters:
        ///   - message: Data to be signed.
        ///   - privateKey: RSA private key.
        /// - Returns: PKCS#1 v1.5 signature bytes.
        /// - Throws: See `sign(_:with:hashAlgorithm:)`.
        public static func sign(_ message: Data, with privateKey: PrivateKey) throws -> Data {
            return try sign(message, with: privateKey, hashAlgorithm: .sha256)
        }
        
        /// Verifies a PKCS#1 v1.5 signature for a message with a chosen hash algorithm.
        ///
        /// The signature is left‑padded with zeros if shorter than the key size (mirroring permissive
        /// behaviors in some SSH tooling). DigestInfo parsing is strict with respect to length and OID.
        ///
        /// - Parameters:
        ///   - signature: Raw signature bytes (may be shorter than modulus length; will be left‑padded for processing).
        ///   - message: Original message that was signed.
        ///   - publicKey: RSA public key.
        ///   - hashAlgorithm: Hash algorithm expected (default `.sha256`).
        /// - Returns: `true` if the signature validates; otherwise `false`.
        /// - Throws: Never; validation failures return `false`.
        public static func verify(_ signature: Data, for message: Data, with publicKey: PublicKey, hashAlgorithm: HashAlgorithm = .sha256) throws -> Bool {
            let keyByteSize = (publicKey.bitSize + 7) / 8
            
            // Handle signature padding like OpenSSH does
            let paddedSignature: Data
            if signature.count > keyByteSize {
                return false
            } else if signature.count < keyByteSize {
                // Pad with zeros at the beginning (left pad)
                paddedSignature = Data(repeating: 0, count: keyByteSize - signature.count) + signature
            } else {
                paddedSignature = signature
            }
            
            // Calculate expected hash based on algorithm
            let expectedHash: Data
            switch hashAlgorithm {
            case .sha1:
                expectedHash = message.sha1DataInsecure()
            case .sha256:
                expectedHash = message.sha256Data()
            case .sha384:
                expectedHash = message.sha384Data()
            case .sha512:
                expectedHash = message.sha512Data()
            }
            
            // Verify: m = s^e mod n
            let s = BigUInt(paddedSignature)
            let m = s.power(publicKey.e, modulus: publicKey.n)
            
            // Convert to Data and unpad
            let paddedMessage = m.serialize().leftPadded(to: keyByteSize)
            guard let digestInfo = try? pkcs1v15Unpad(paddedMessage, forEncryption: false) else {
                return false
            }
            
            // Extract hash from DigestInfo and compare
            guard let extractedHash = extractHashFromDigestInfo(digestInfo, algorithm: hashAlgorithm) else {
                return false
            }
            
            return extractedHash == expectedHash
        }
        
        /// Convenience overload that verifies a signature assuming SHA‑256 was used.
        ///
        /// - Parameters:
        ///   - signature: Raw signature bytes.
        ///   - message: Original message.
        ///   - publicKey: RSA public key.
        /// - Returns: `true` if valid; otherwise `false`.
        public static func verify(_ signature: Data, for message: Data, with publicKey: PublicKey) throws -> Bool {
            return try verify(signature, for: message, with: publicKey, hashAlgorithm: .sha256)
        }
        
        // MARK: - Raw Operations
        
        /// Performs the raw modular exponentiation for encryption:  c = m^e mod n.
        ///
        /// - Parameters:
        ///   - message: Integer message representative (< n).
        ///   - publicKey: RSA public key.
        /// - Returns: Ciphertext integer.
        /// - Important: No padding is applied. Callers must supply a properly encoded representative.
        public static func rawEncrypt(_ message: BigUInt, with publicKey: PublicKey) -> BigUInt {
            return message.power(publicKey.e, modulus: publicKey.n)
        }
        
        /// Performs the raw modular exponentiation for decryption using CRT: m = c^d mod n.
        ///
        /// - Parameters:
        ///   - ciphertext: Integer ciphertext (< n).
        ///   - privateKey: RSA private key.
        /// - Returns: Decrypted integer representative.
        /// - Warning: No padding removal or validation is performed.
        public static func rawDecrypt(_ ciphertext: BigUInt, with privateKey: PrivateKey) -> BigUInt {
            return decryptWithCRT(ciphertext, privateKey: privateKey)
        }
        
        // MARK: - PEM/DER Parsing
        
        /// Extracts the RSA modulus and exponent from a DER encoded SubjectPublicKeyInfo (SPKI) structure.
        ///
        /// Minimal ASN.1 parsing is performed strictly for the expected RSA public key layout.
        ///
        /// - Parameter spkiDERRepresentation: DER bytes of the SPKI wrapper containing an `RSAPublicKey`.
        /// - Returns: Tuple `(modulus, exponent)` as big‑endian data blobs.
        /// - Throws: `SSHKeyError.invalidFormat` for structural violations or `SSHKeyError.invalidKeyData` for length inconsistencies.
        /// - Important: This parser is intentionally narrow and not a full ASN.1 validator.
        public static func extractPublicKeyComponents(from spkiDERRepresentation: Data) throws -> (modulus: Data, exponent: Data) {
            // SPKI structure for RSA:
            // SubjectPublicKeyInfo ::= SEQUENCE {
            //     algorithm AlgorithmIdentifier,
            //     subjectPublicKey BIT STRING
            // }
            // The BIT STRING contains:
            // RSAPublicKey ::= SEQUENCE {
            //     modulus           INTEGER,  -- n
            //     publicExponent    INTEGER   -- e
            // }
            
            var index = 0
            let data = spkiDERRepresentation
            
            // Check outer SEQUENCE tag (SubjectPublicKeyInfo)
            guard index < data.count, data[index] == 0x30 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            // Skip outer SEQUENCE length
            let (_, outerLengthSize) = try parseASN1Length(data: data, startIndex: index)
            index += outerLengthSize
            
            // Skip AlgorithmIdentifier SEQUENCE
            guard index < data.count, data[index] == 0x30 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            let (algIdLength, algIdLengthSize) = try parseASN1Length(data: data, startIndex: index)
            index += algIdLengthSize + algIdLength
            
            // Parse BIT STRING containing the public key
            guard index < data.count, data[index] == 0x03 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            let (_, bitStringLengthSize) = try parseASN1Length(data: data, startIndex: index)
            index += bitStringLengthSize
            
            // Skip the padding byte of BIT STRING
            guard index < data.count, data[index] == 0x00 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            // Now we're at the RSAPublicKey SEQUENCE
            guard index < data.count, data[index] == 0x30 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            // Skip RSAPublicKey SEQUENCE length
            let (_, rsaPubKeyLengthSize) = try parseASN1Length(data: data, startIndex: index)
            index += rsaPubKeyLengthSize
            
            // Parse modulus (INTEGER)
            guard index < data.count, data[index] == 0x02 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            let (modulusLength, modulusLengthSize) = try parseASN1Length(data: data, startIndex: index)
            index += modulusLengthSize
            
            guard index + modulusLength <= data.count else {
                throw SSHKeyError.invalidKeyData
            }
            
            let modulus = data[index..<(index + modulusLength)]
            index += modulusLength
            
            // Parse exponent (INTEGER)
            guard index < data.count, data[index] == 0x02 else {
                throw SSHKeyError.invalidFormat
            }
            index += 1
            
            let (exponentLength, exponentLengthSize) = try parseASN1Length(data: data, startIndex: index)
            index += exponentLengthSize
            
            guard index + exponentLength <= data.count else {
                throw SSHKeyError.invalidKeyData
            }
            
            let exponent = data[index..<(index + exponentLength)]
            
            return (modulus: Data(modulus), exponent: Data(exponent))
        }
        
        /// Parse ASN.1 length field
        private static func parseASN1Length(data: Data, startIndex: Int) throws -> (length: Int, bytesUsed: Int) {
            guard startIndex < data.count else {
                throw SSHKeyError.invalidFormat
            }
            
            let firstByte = data[startIndex]
            
            if firstByte & 0x80 == 0 {
                // Short form: length is in the first byte
                return (length: Int(firstByte), bytesUsed: 1)
            } else {
                // Long form: first byte indicates number of length bytes
                let lengthOfLength = Int(firstByte & 0x7F)
                guard lengthOfLength > 0 && lengthOfLength <= 4 else {
                    throw SSHKeyError.invalidFormat
                }
                
                guard startIndex + 1 + lengthOfLength <= data.count else {
                    throw SSHKeyError.invalidKeyData
                }
                
                var length = 0
                for i in 0..<lengthOfLength {
                    length = (length << 8) | Int(data[startIndex + 1 + i])
                }
                
                return (length: length, bytesUsed: 1 + lengthOfLength)
            }
        }
        
        // MARK: - Helper Functions
        
        /// Small prime list for trial division sieve (first primes up to < 1000, excluding 2).
        /// Using UInt16 keeps them compact; this significantly cuts Miller–Rabin invocations.
        private static let smallPrimes: [UInt16] = [
            3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
            101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,
            211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,
            337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,
            461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,
            601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,
            739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,
            881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
        ]

        /// Recommended Miller–Rabin rounds based on bit size (probability of composite slipping past is negligible).
        private static func recommendedMillerRabinRounds(bitWidth: Int) -> Int {
            switch bitWidth {
            case 0..<256: return 12
            case 256..<512: return 10
            case 512..<1024: return 8
            case 1024..<2048: return 7
            default: return 6 // 2048 bits and above
            }
        }

        /// Quick trial division against small primes (excluding 2, we ensure oddness earlier).
        private static func passesSmallPrimeSieve(_ n: BigUInt) -> Bool {
            for p in smallPrimes {
                let prime = BigUInt(p)
                if n == prime { return true }
                if n % prime == 0 { return false }
            }
            return true
        }

        /// Generate a prime number with specified bit size; ensures top two bits are set so the
        /// eventual modulus achieves the target bit length when both primes share this property.
        private static func generatePrime(bitSize: Int, ensureCoprimeWith e: BigUInt? = nil) throws -> BigUInt {
            precondition(bitSize >= 16, "Prime size too small")
            let byteCount = bitSize / 8
            let rounds = recommendedMillerRabinRounds(bitWidth: bitSize)
            let maxAttempts = 25_000
            var attempts = 0
            while attempts < maxAttempts {
                attempts += 1
                var randomBytes = try Data.generateSecureRandomBytes(count: byteCount)
                // Set top two bits to guarantee candidate bit size and later modulus size.
                randomBytes[0] |= 0xC0
                // Force odd
                randomBytes[randomBytes.count - 1] |= 0x01
                let candidate = BigUInt(randomBytes)
                // Bit width sanity
                guard candidate.bitWidth == bitSize else { continue }
                // Small prime sieve
                guard passesSmallPrimeSieve(candidate) else { continue }
                // Optional coprime check (Euler totient compatibility with public exponent)
                if let e = e, gcd(e, candidate - 1) != 1 { continue }
                // Miller–Rabin probabilistic test
                if isProbablePrime(candidate, rounds: rounds) { return candidate }
            }
            return generateFallbackPrime(bitSize: bitSize)
        }
        
        /// Generate a fallback prime when random generation fails
        private static func generateFallbackPrime(bitSize: Int) -> BigUInt {
            // Start with 2^(bitSize-1) + 1 and search for next prime
            var candidate = BigUInt(1) << (bitSize - 1)
            candidate |= 1  // Make odd
            
            // Use a conservative higher round count for deterministic fallback search.
            while !isProbablePrime(candidate, rounds: recommendedMillerRabinRounds(bitWidth: bitSize) + 2) {
                candidate += 2
            }
            
            return candidate
        }
        
        /// Miller-Rabin primality test (probabilistic)
        private static func isProbablePrime(_ n: BigUInt, rounds: Int) -> Bool {
            if n <= 1 { return false }
            if n <= 3 { return true }
            if n % 2 == 0 { return false }
            
            // Write n-1 as 2^r * d
            var d = n - 1
            var r = 0
            while d % 2 == 0 {
                d /= 2
                r += 1
            }
            
            // Witness loop
            for _ in 0..<rounds {
                // Random base in [2, n-2]
                let a = BigUInt.randomInteger(lessThan: n - 3) + 2
                var x = a.power(d, modulus: n)
                
                if x == 1 || x == n - 1 {
                    continue
                }
                
                var continueWitnessLoop = false
                for _ in 0..<r - 1 {
                    x = (x * x) % n
                    if x == n - 1 {
                        continueWitnessLoop = true
                        break
                    }
                }
                
                if !continueWitnessLoop {
                    return false
                }
            }
            
            return true
        }

        /// Euclidean greatest common divisor (BigUInt).
        private static func gcd(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
            var x = a
            var y = b
            while y != 0 { (x, y) = (y, x % y) }
            return x
        }
        
        /// Calculate modular inverse using Extended Euclidean Algorithm
        private static func modularInverse(_ a: BigUInt, _ m: BigUInt) -> BigUInt? {
            // Extended Euclidean Algorithm on integers
            // Finds t such that a*t ≡ 1 (mod m), if gcd(a, m) == 1
            if m == 1 { return 0 }

            var r = BigInt(m)
            var newR = BigInt(a % m)
            var t = BigInt(0)
            var newT = BigInt(1)

            while newR != 0 {
                let q = r / newR
                (r, newR) = (newR, r - q * newR)
                (t, newT) = (newT, t - q * newT)
            }

            // If gcd(a, m) != 1, inverse doesn't exist
            if r != 1 { return nil }

            if t < 0 { t += BigInt(m) }
            return BigUInt(t)
        }
        
        /// Decrypt using Chinese Remainder Theorem optimization
        private static func decryptWithCRT(_ c: BigUInt, privateKey: PrivateKey) -> BigUInt {
            // m1 = c^dP mod p
            let m1 = c.power(privateKey.dP, modulus: privateKey.p)
            
            // m2 = c^dQ mod q
            let m2 = c.power(privateKey.dQ, modulus: privateKey.q)
            
            // h = qInv * (m1 - m2) mod p
            let diff = m1 >= m2 ? m1 - m2 : privateKey.p - (m2 - m1)
            let h = (privateKey.qInv * diff) % privateKey.p
            
            // m = m2 + h * q
            return m2 + h * privateKey.q
        }
        
        // MARK: - Padding
        
        /// Apply PKCS#1 v1.5 padding
        private static func pkcs1v15Pad(_ message: Data, keyByteSize: Int, forEncryption: Bool) throws -> Data {
            let paddingType: UInt8 = forEncryption ? 0x02 : 0x01
            let minPaddingLength = 8
            
            guard message.count <= keyByteSize - minPaddingLength - 3 else {
                throw SSHKeyError.invalidKeyData
            }
            
            var padded = Data()
            padded.append(0x00)
            padded.append(paddingType)
            
            let paddingLength = keyByteSize - message.count - 3
            
            if forEncryption {
                // Random non-zero padding for encryption
                var padding = try Data.generateSecureRandomBytes(count: paddingLength)
                // Ensure no zero bytes
                for i in 0..<padding.count {
                    if padding[i] == 0 {
                        padding[i] = 1
                    }
                }
                padded.append(padding)
            } else {
                // 0xFF padding for signing
                padded.append(Data(repeating: 0xFF, count: paddingLength))
            }
            
            padded.append(0x00)
            padded.append(message)
            
            return padded
        }
        
        /// Remove PKCS#1 v1.5 padding
        private static func pkcs1v15Unpad(_ padded: Data, forEncryption: Bool) throws -> Data {
            guard padded.count >= 11 else {
                throw SSHKeyError.invalidKeyData
            }
            
            guard padded[0] == 0x00 else {
                throw SSHKeyError.invalidKeyData
            }
            
            let expectedPaddingType: UInt8 = forEncryption ? 0x02 : 0x01
            guard padded[1] == expectedPaddingType else {
                throw SSHKeyError.invalidKeyData
            }
            
            // Find the 0x00 separator
            var separatorIndex = -1
            for i in 2..<padded.count {
                if padded[i] == 0x00 {
                    separatorIndex = i
                    break
                }
            }
            
            guard separatorIndex >= 10 else {
                throw SSHKeyError.invalidKeyData
            }
            
            return padded[(separatorIndex + 1)...]
        }
        
        // MARK: - DigestInfo
        
        public enum HashAlgorithm {
            case sha1
            case sha256
            case sha384
            case sha512
            
            var oid: Data {
                switch self {
                case .sha1:
                    return Data([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14])
                case .sha256:
                    return Data([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20])
                case .sha384:
                    return Data([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30])
                case .sha512:
                    return Data([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40])
                }
            }
            
            var digestLength: Int {
                switch self {
                case .sha1: return 20
                case .sha256: return 32
                case .sha384: return 48
                case .sha512: return 64
                }
            }
        }
        
        /// Create DigestInfo structure
        private static func createDigestInfo(hash: Data, algorithm: HashAlgorithm) -> Data {
            var digestInfo = Data()
            digestInfo.append(algorithm.oid)
            digestInfo.append(hash)
            return digestInfo
        }
        
        /// Extract hash from DigestInfo structure
        private static func extractHashFromDigestInfo(_ digestInfo: Data, algorithm: HashAlgorithm) -> Data? {
            let oid = algorithm.oid
            guard digestInfo.count == oid.count + algorithm.digestLength else {
                return nil
            }
            guard digestInfo.prefix(oid.count) == oid else {
                return nil
            }
            return digestInfo.suffix(algorithm.digestLength)
        }
    }
}
