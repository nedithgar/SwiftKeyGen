import Foundation
import BigInt
import Crypto

// MARK: - Insecure RSA Implementation

extension Insecure {
    /// Complete RSA implementation for educational and compatibility purposes
    /// WARNING: This implementation is for internal use only and may not be secure against all attacks
    public enum RSA {
        
        // MARK: - Key Generation
        
        /// Generate an RSA key pair with the specified bit size
        public static func generateKeyPair(bitSize: Int = 2048) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
            guard bitSize >= 512 && bitSize % 8 == 0 else {
                throw SSHKeyError.invalidKeySize(bitSize, "RSA key size must be at least 512 bits and a multiple of 8")
            }
            
            let maxAttempts = 100
            var attempts = 0
            
            while attempts < maxAttempts {
                attempts += 1
                
                // Generate two large prime numbers
                let p = generatePrime(bitSize: bitSize / 2)
                let q = generatePrime(bitSize: bitSize / 2)
                
                // Calculate n = p * q
                let n = p * q
                
                // Check if n has the correct bit size
                let nBitLength = n.bitWidth
                if nBitLength < bitSize {
                    // Try again if n is too small
                    continue
                }
                
                // Calculate Euler's totient: φ(n) = (p-1)(q-1)
                let phi = (p - 1) * (q - 1)
                
                // Choose public exponent e (commonly 65537)
                let e = BigUInt(65537)
                
                // Calculate private exponent d such that d * e ≡ 1 (mod φ(n))
                guard let d = modularInverse(e, phi) else {
                    // Try again if we can't find modular inverse
                    continue
                }
                
                let publicKey = PublicKey(n: n, e: e)
                let privateKey = PrivateKey(n: n, e: e, d: d, p: p, q: q)
                
                return (privateKey, publicKey)
            }
            
            throw SSHKeyError.generationFailed("Failed to generate RSA key pair after \(maxAttempts) attempts")
        }
        
        // MARK: - Key Types
        
        /// RSA Public Key
        public struct PublicKey {
            public let n: BigUInt  // modulus
            public let e: BigUInt  // public exponent
            
            public init(n: BigUInt, e: BigUInt) {
                self.n = n
                self.e = e
            }
            
            /// Initialize from modulus and exponent data
            public init(modulus: Data, exponent: Data) throws {
                self.n = BigUInt(modulus)
                self.e = BigUInt(exponent)
            }
            
            /// Get the modulus as Data
            public var modulusData: Data {
                return n.serialize()
            }
            
            /// Get the exponent as Data
            public var exponentData: Data {
                return e.serialize()
            }
            
            /// Key size in bits
            public var bitSize: Int {
                return n.bitWidth
            }
        }
        
        /// RSA Private Key
        public struct PrivateKey {
            public let n: BigUInt   // modulus
            public let e: BigUInt   // public exponent
            public let d: BigUInt   // private exponent
            public let p: BigUInt   // prime p
            public let q: BigUInt   // prime q
            
            // Chinese Remainder Theorem optimization values
            public let dP: BigUInt  // d mod (p-1)
            public let dQ: BigUInt  // d mod (q-1)
            public let qInv: BigUInt // q^(-1) mod p
            
            public init(n: BigUInt, e: BigUInt, d: BigUInt, p: BigUInt, q: BigUInt) {
                self.n = n
                self.e = e
                self.d = d
                self.p = p
                self.q = q
                
                // Calculate CRT values
                self.dP = d % (p - 1)
                self.dQ = d % (q - 1)
                self.qInv = modularInverse(q, p)!
            }
            
            /// Get the public key
            public var publicKey: PublicKey {
                return PublicKey(n: n, e: e)
            }
            
            /// Key size in bits
            public var bitSize: Int {
                return n.bitWidth
            }
        }
        
        // MARK: - Encryption/Decryption
        
        /// Encrypt data using RSA public key (PKCS#1 v1.5 padding)
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
        
        /// Decrypt data using RSA private key (PKCS#1 v1.5 padding)
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
        
        /// Sign data using RSA private key with specified hash algorithm
        public static func sign(_ message: Data, with privateKey: PrivateKey, hashAlgorithm: HashAlgorithm = .sha256) throws -> Data {
            let keyByteSize = (privateKey.bitSize + 7) / 8
            
            // Calculate hash based on algorithm
            let hash: Data
            switch hashAlgorithm {
            case .sha1:
                let digest = Insecure.SHA1.hash(data: message)
                hash = Data(digest)
            case .sha256:
                let digest = SHA256.hash(data: message)
                hash = Data(digest)
            case .sha384:
                let digest = SHA384.hash(data: message)
                hash = Data(digest)
            case .sha512:
                let digest = SHA512.hash(data: message)
                hash = Data(digest)
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
        
        /// Sign data using RSA private key (PKCS#1 v1.5 with SHA256) - convenience method
        public static func sign(_ message: Data, with privateKey: PrivateKey) throws -> Data {
            return try sign(message, with: privateKey, hashAlgorithm: .sha256)
        }
        
        /// Verify RSA signature with specified hash algorithm
        public static func verify(_ signature: Data, for message: Data, with publicKey: PublicKey, hashAlgorithm: HashAlgorithm = .sha256) throws -> Bool {
            let keyByteSize = (publicKey.bitSize + 7) / 8
            
            guard signature.count == keyByteSize else {
                return false
            }
            
            // Calculate expected hash based on algorithm
            let expectedHash: Data
            switch hashAlgorithm {
            case .sha1:
                let digest = Insecure.SHA1.hash(data: message)
                expectedHash = Data(digest)
            case .sha256:
                let digest = SHA256.hash(data: message)
                expectedHash = Data(digest)
            case .sha384:
                let digest = SHA384.hash(data: message)
                expectedHash = Data(digest)
            case .sha512:
                let digest = SHA512.hash(data: message)
                expectedHash = Data(digest)
            }
            
            // Verify: m = s^e mod n
            let s = BigUInt(signature)
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
        
        /// Verify RSA signature (PKCS#1 v1.5 with SHA256) - convenience method
        public static func verify(_ signature: Data, for message: Data, with publicKey: PublicKey) throws -> Bool {
            return try verify(signature, for: message, with: publicKey, hashAlgorithm: .sha256)
        }
        
        // MARK: - Raw Operations
        
        /// Raw RSA encryption: c = m^e mod n
        public static func rawEncrypt(_ message: BigUInt, with publicKey: PublicKey) -> BigUInt {
            return message.power(publicKey.e, modulus: publicKey.n)
        }
        
        /// Raw RSA decryption: m = c^d mod n
        public static func rawDecrypt(_ ciphertext: BigUInt, with privateKey: PrivateKey) -> BigUInt {
            return decryptWithCRT(ciphertext, privateKey: privateKey)
        }
        
        // MARK: - PEM/DER Parsing
        
        /// Extract RSA public key components (modulus and exponent) from SPKI DER representation
        /// - Parameter spkiDERRepresentation: The SPKI DER-encoded RSA public key
        /// - Returns: A tuple containing the modulus and exponent as Data
        /// - Throws: SSHKeyError if parsing fails
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
        
        /// Generate a prime number with specified bit size
        private static func generatePrime(bitSize: Int) -> BigUInt {
            let maxAttempts = 10000 // Prevent infinite loops
            var attempts = 0
            
            while attempts < maxAttempts {
                attempts += 1
                
                var randomBytes = Data(count: bitSize / 8)
                randomBytes.withUnsafeMutableBytes { bytes in
                    guard let baseAddress = bytes.baseAddress else { return }
                    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, baseAddress)
                }
                
                // Ensure the number has the correct bit size
                randomBytes[0] |= 0x80  // Set MSB
                randomBytes[randomBytes.count - 1] |= 0x01  // Ensure odd
                
                let candidate = BigUInt(randomBytes)
                
                // Verify the candidate has the correct bit size
                let bitLength = candidate.bitWidth
                if bitLength == bitSize && isProbablePrime(candidate) {
                    return candidate
                }
            }
            
            // Fallback: generate a known prime of the correct size
            // This ensures we always return a valid prime
            return generateFallbackPrime(bitSize: bitSize)
        }
        
        /// Generate a fallback prime when random generation fails
        private static func generateFallbackPrime(bitSize: Int) -> BigUInt {
            // Start with 2^(bitSize-1) + 1 and search for next prime
            var candidate = BigUInt(1) << (bitSize - 1)
            candidate |= 1  // Make odd
            
            while !isProbablePrime(candidate) {
                candidate += 2
            }
            
            return candidate
        }
        
        /// Miller-Rabin primality test
        private static func isProbablePrime(_ n: BigUInt, rounds: Int = 20) -> Bool {
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
                let a = BigUInt.randomInteger(lessThan: n - 2) + 2
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
        
        /// Calculate modular inverse using Extended Euclidean Algorithm
        private static func modularInverse(_ a: BigUInt, _ m: BigUInt) -> BigUInt? {
            if m == 1 { return 0 }
            
            var a = a % m
            var m = m
            var x0 = BigInt(0)
            var x1 = BigInt(1)
            
            let maxIterations = 100000 // Prevent infinite loops
            var iterations = 0
            
            while a > 1 && iterations < maxIterations {
                iterations += 1
                
                let q = BigInt(a / m)
                
                var t = BigInt(m)
                m = a
                a = BigUInt(t % BigInt(a))
                
                t = x0
                x0 = x1 - q * x0
                x1 = t
            }
            
            if iterations >= maxIterations {
                return nil // Failed to find modular inverse
            }
            
            if x1 < 0 {
                x1 += BigInt(m)
            }
            
            return BigUInt(x1)
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
                var padding = Data(count: paddingLength)
                padding.withUnsafeMutableBytes { bytes in
                    guard let baseAddress = bytes.baseAddress else { return }
                    _ = SecRandomCopyBytes(kSecRandomDefault, paddingLength, baseAddress)
                }
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

// MARK: - Data Extensions

extension Data {
    /// Left pad data to specified size
    fileprivate func leftPadded(to size: Int) -> Data {
        guard count < size else { return self }
        return Data(repeating: 0, count: size - count) + self
    }
}

// MARK: - Hash Functions (using CryptoKit)

fileprivate enum SHA256 {
    static func hash(data: Data) -> Data {
        let digest = Crypto.SHA256.hash(data: data)
        return Data(digest)
    }
}

fileprivate enum SHA384 {
    static func hash(data: Data) -> Data {
        let digest = Crypto.SHA384.hash(data: data)
        return Data(digest)
    }
}

fileprivate enum SHA512 {
    static func hash(data: Data) -> Data {
        let digest = Crypto.SHA512.hash(data: data)
        return Data(digest)
    }
}