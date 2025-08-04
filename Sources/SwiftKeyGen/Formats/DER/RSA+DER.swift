import Foundation
import Crypto
import BigInt

extension Insecure.RSA.PrivateKey {
    /// Generate PKCS#1 DER encoding for RSA private key
    /// RSAPrivateKey ::= SEQUENCE {
    ///   version           Version,
    ///   modulus           INTEGER,  -- n
    ///   publicExponent    INTEGER,  -- e
    ///   privateExponent   INTEGER,  -- d
    ///   prime1            INTEGER,  -- p
    ///   prime2            INTEGER,  -- q
    ///   exponent1         INTEGER,  -- d mod (p-1)
    ///   exponent2         INTEGER,  -- d mod (q-1)
    ///   coefficient       INTEGER,  -- (inverse of q) mod p
    /// }
    func pkcs1DERRepresentation() throws -> Data {
        var encoder = DEREncoder()
        
        // SEQUENCE header
        encoder.encodeSequence { sequenceEncoder in
            // version (0 for two-prime RSA)
            sequenceEncoder.encodeInteger(BigUInt(0))
            
            // modulus n
            sequenceEncoder.encodeInteger(n)
            
            // publicExponent e
            sequenceEncoder.encodeInteger(e)
            
            // privateExponent d
            sequenceEncoder.encodeInteger(d)
            
            // prime1 p
            sequenceEncoder.encodeInteger(p)
            
            // prime2 q
            sequenceEncoder.encodeInteger(q)
            
            // exponent1 dP (d mod (p-1))
            sequenceEncoder.encodeInteger(dP)
            
            // exponent2 dQ (d mod (q-1))
            sequenceEncoder.encodeInteger(dQ)
            
            // coefficient qInv
            sequenceEncoder.encodeInteger(qInv)
        }
        
        return encoder.data
    }
    
    /// Generate PKCS#1 PEM representation
    func pkcs1PEMRepresentation() throws -> String {
        let derData = try pkcs1DERRepresentation()
        let base64 = derData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        
        return """
        -----BEGIN RSA PRIVATE KEY-----
        \(base64)
        -----END RSA PRIVATE KEY-----
        """ + "\n"
    }
}

extension Insecure.RSA.PublicKey {
    /// Generate PKCS#1 DER encoding for RSA public key
    /// RSAPublicKey ::= SEQUENCE {
    ///   modulus           INTEGER,  -- n
    ///   publicExponent    INTEGER   -- e
    /// }
    func pkcs1DERRepresentation() throws -> Data {
        var encoder = DEREncoder()
        
        encoder.encodeSequence { sequenceEncoder in
            // modulus n
            sequenceEncoder.encodeInteger(n)
            
            // publicExponent e
            sequenceEncoder.encodeInteger(e)
        }
        
        return encoder.data
    }
    
    /// Generate SubjectPublicKeyInfo DER encoding (PKCS#8)
    /// SubjectPublicKeyInfo ::= SEQUENCE {
    ///   algorithm         AlgorithmIdentifier,
    ///   subjectPublicKey  BIT STRING
    /// }
    func subjectPublicKeyInfoDERRepresentation() throws -> Data {
        var encoder = DEREncoder()
        
        // Get the public key DER first to handle the throw
        let publicKeyDER = try pkcs1DERRepresentation()
        
        encoder.encodeSequence { sequenceEncoder in
            // AlgorithmIdentifier
            sequenceEncoder.encodeSequence { algEncoder in
                // rsaEncryption OID: 1.2.840.113549.1.1.1
                algEncoder.encodeObjectIdentifier([1, 2, 840, 113549, 1, 1, 1])
                // parameters NULL
                algEncoder.encodeNull()
            }
            
            // subjectPublicKey BIT STRING
            sequenceEncoder.encodeBitString(publicKeyDER)
        }
        
        return encoder.data
    }
    
    /// Generate PKCS#1 PEM representation for public key
    func pkcs1PEMRepresentation() throws -> String {
        let derData = try subjectPublicKeyInfoDERRepresentation()
        let base64 = derData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        
        return """
        -----BEGIN PUBLIC KEY-----
        \(base64)
        -----END PUBLIC KEY-----
        """ + "\n"
    }
}

// MARK: - DER Encoder

private struct DEREncoder {
    var data = Data()
    
    // ASN.1 tags
    private enum Tag: UInt8 {
        case integer = 0x02
        case bitString = 0x03
        case null = 0x05
        case objectIdentifier = 0x06
        case sequence = 0x30
    }
    
    mutating func encodeLength(_ length: Int) {
        if length < 128 {
            data.append(UInt8(length))
        } else if length < 256 {
            data.append(0x81)
            data.append(UInt8(length))
        } else if length < 65536 {
            data.append(0x82)
            data.append(UInt8((length >> 8) & 0xff))
            data.append(UInt8(length & 0xff))
        } else {
            // For larger lengths, we'd need more bytes
            data.append(0x83)
            data.append(UInt8((length >> 16) & 0xff))
            data.append(UInt8((length >> 8) & 0xff))
            data.append(UInt8(length & 0xff))
        }
    }
    
    mutating func encodeInteger(_ value: BigUInt) {
        var bytes = value.bytes
        
        // Add leading zero if high bit is set (to keep it positive)
        if !bytes.isEmpty && bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        
        // Remove leading zeros except if the next byte has high bit set
        while bytes.count > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
            bytes.removeFirst()
        }
        
        data.append(Tag.integer.rawValue)
        encodeLength(bytes.count)
        data.append(contentsOf: bytes)
    }
    
    mutating func encodeNull() {
        data.append(Tag.null.rawValue)
        data.append(0x00)
    }
    
    mutating func encodeObjectIdentifier(_ oid: [Int]) {
        var oidBytes = Data()
        
        // First two components are encoded specially
        if oid.count >= 2 {
            oidBytes.append(UInt8(oid[0] * 40 + oid[1]))
            
            // Encode remaining components
            for i in 2..<oid.count {
                encodeOIDComponent(oid[i], into: &oidBytes)
            }
        }
        
        data.append(Tag.objectIdentifier.rawValue)
        encodeLength(oidBytes.count)
        data.append(oidBytes)
    }
    
    private func encodeOIDComponent(_ value: Int, into data: inout Data) {
        if value < 128 {
            data.append(UInt8(value))
        } else {
            var bytes: [UInt8] = []
            var v = value
            
            // Encode in base 128
            while v > 0 {
                bytes.insert(UInt8(v & 0x7f), at: 0)
                v >>= 7
            }
            
            // Set high bit on all bytes except the last
            for i in 0..<(bytes.count - 1) {
                bytes[i] |= 0x80
            }
            
            data.append(contentsOf: bytes)
        }
    }
    
    mutating func encodeBitString(_ bitData: Data) {
        data.append(Tag.bitString.rawValue)
        encodeLength(bitData.count + 1)
        data.append(0x00) // No unused bits
        data.append(bitData)
    }
    
    mutating func encodeSequence(_ closure: (inout DEREncoder) throws -> Void) rethrows {
        var sequenceEncoder = DEREncoder()
        try closure(&sequenceEncoder)
        
        data.append(Tag.sequence.rawValue)
        encodeLength(sequenceEncoder.data.count)
        data.append(sequenceEncoder.data)
    }
}

// Helper extension to get bytes from BigUInt
extension BigUInt {
    var bytes: [UInt8] {
        // Convert BigUInt to bytes (big-endian)
        var result: [UInt8] = []
        var value = self
        
        if value == 0 {
            return [0]
        }
        
        while value > 0 {
            result.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        
        return result
    }
}