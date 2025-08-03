import Foundation

struct ASN1Parser {
    private let data: Data
    private var offset = 0
    
    init(data: Data) {
        self.data = data
    }
    
    // Check if there's more data to parse
    var hasMoreData: Bool {
        return offset < data.count
    }
    
    mutating func parseRSAPublicKey() throws -> (modulus: Data, exponent: Data) {
        // RSA public keys in SubjectPublicKeyInfo format
        // SEQUENCE {
        //   SEQUENCE {
        //     OBJECT IDENTIFIER rsaEncryption
        //     NULL
        //   }
        //   BIT STRING {
        //     SEQUENCE {
        //       INTEGER modulus
        //       INTEGER publicExponent
        //     }
        //   }
        // }
        
        // Parse outer SEQUENCE
        guard offset < data.count, data[offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        _ = try parseLength()
        
        // Parse algorithm identifier SEQUENCE
        guard offset < data.count, data[offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        let algIdLength = try parseLength()
        
        // Skip the algorithm identifier content
        offset += Int(algIdLength)
        
        // Parse BIT STRING
        guard offset < data.count, data[offset] == 0x03 else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        _ = try parseLength()
        
        // Skip bit string padding byte
        guard offset < data.count else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        
        // Parse inner SEQUENCE containing modulus and exponent
        guard offset < data.count, data[offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        _ = try parseLength()
        
        // Parse modulus
        guard let modulus = try parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse exponent
        guard let exponent = try parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        return (modulus: modulus, exponent: exponent)
    }
    
    private mutating func skipSequence() throws {
        guard offset < data.count, data[offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        let length = try parseLength()
        offset += Int(length)
    }
    
    
    private mutating func parseLength() throws -> Int {
        guard offset < data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let firstByte = data[offset]
        offset += 1
        
        if firstByte & 0x80 == 0 {
            // Short form
            return Int(firstByte)
        } else {
            // Long form
            let numBytes = Int(firstByte & 0x7F)
            guard offset + numBytes <= data.count else {
                throw SSHKeyError.invalidKeyData
            }
            
            var length = 0
            for _ in 0..<numBytes {
                length = (length << 8) | Int(data[offset])
                offset += 1
            }
            return length
        }
    }
    
    // MARK: - Additional Parsing Methods for PEM Support
    
    mutating func parseSequence() throws -> Data? {
        guard offset < data.count, data[offset] == 0x30 else {
            return nil
        }
        offset += 1
        
        let length = try parseLength()
        guard offset + Int(length) <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let sequenceData = data.subdata(in: offset..<offset+Int(length))
        offset += Int(length)
        
        return sequenceData
    }
    
    mutating func parseInteger() throws -> Data? {
        guard offset < data.count, data[offset] == 0x02 else {
            return nil
        }
        offset += 1
        
        let length = try parseLength()
        guard offset + Int(length) <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let integerData = data.subdata(in: offset..<offset+Int(length))
        offset += Int(length)
        
        return integerData
    }
    
    mutating func parseObjectIdentifier() throws -> Data? {
        guard offset < data.count, data[offset] == 0x06 else {
            return nil
        }
        offset += 1
        
        let length = try parseLength()
        guard offset + Int(length) <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let oidData = data.subdata(in: offset..<offset+Int(length))
        offset += Int(length)
        
        return oidData
    }
    
    mutating func parseBitString() throws -> Data? {
        guard offset < data.count, data[offset] == 0x03 else {
            return nil
        }
        offset += 1
        
        let length = try parseLength()
        guard offset + Int(length) <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Skip the padding byte
        guard offset < data.count else {
            throw SSHKeyError.invalidKeyData
        }
        offset += 1
        
        // Return the actual bit string data (minus the padding byte)
        let bitStringData = data.subdata(in: offset..<offset+Int(length-1))
        offset += Int(length - 1)
        
        return bitStringData
    }
    
    mutating func parseNull() throws -> Bool {
        guard offset + 2 <= data.count,
              data[offset] == 0x05,
              data[offset + 1] == 0x00 else {
            return false
        }
        offset += 2
        return true
    }
    
    mutating func parseOctetString() throws -> Data? {
        guard offset < data.count, data[offset] == 0x04 else {
            return nil
        }
        offset += 1
        
        let length = try parseLength()
        guard offset + Int(length) <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let octetStringData = data.subdata(in: offset..<offset+Int(length))
        offset += Int(length)
        
        return octetStringData
    }
}