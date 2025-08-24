import Foundation

struct SSHEncoder {
    var data = Data()
    
    mutating func encodeString(_ string: String) {
        guard let stringData = string.data(using: .utf8) else { return }
        encodeData(stringData)
    }
    
    mutating func encodeData(_ data: Data) {
        encodeUInt32(UInt32(data.count))
        self.data.append(data)
    }
    
    mutating func encodeUInt32(_ value: UInt32) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: 4))
    }
    
    mutating func encodeUInt64(_ value: UInt64) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: 8))
    }
    
    mutating func encodeBigInt(_ data: Data) {
        var bytes = Data(data) // Ensure we have a mutable copy
        
        // Add a leading zero byte if the high bit is set (to ensure positive number)
        if !bytes.isEmpty && bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        
        // Remove leading zeros (except if it's needed for sign)
        // Use index-based approach instead of removeFirst() to avoid potential issues
        var startIndex = 0
        while startIndex + 1 < bytes.count && bytes[startIndex] == 0 && bytes[startIndex + 1] & 0x80 == 0 {
            startIndex += 1
        }
        
        if startIndex > 0 {
            bytes = Data(bytes.suffix(from: startIndex))
        }
        
        encodeData(bytes)
    }
    
    func encode() -> Data {
        return data
    }
}

struct SSHDecoder {
    private var data: Data
    private var offset = 0
    
    init(data: Data) {
        self.data = data
    }
    
    mutating func decodeUInt32() throws -> UInt32 {
        guard offset + 4 <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let value = data.subdata(in: offset..<offset+4).withUnsafeBytes { bytes in
            return UInt32(bigEndian: bytes.load(as: UInt32.self))
        }
        
        offset += 4
        return value
    }
    
    mutating func decodeData() throws -> Data {
        let length = try decodeUInt32()
        guard offset + Int(length) <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let result = data.subdata(in: offset..<offset+Int(length))
        offset += Int(length)
        return result
    }
    
    mutating func decodeString() throws -> String {
        let data = try decodeData()
        guard let string = String(data: data, encoding: .utf8) else {
            throw SSHKeyError.invalidKeyData
        }
        return string
    }
    
    var hasMoreData: Bool {
        return offset < data.count
    }
    
    var remaining: Int {
        return data.count - offset
    }
    
    mutating func decodeBytes(count: Int) throws -> [UInt8] {
        guard offset + count <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let result = Array(data.subdata(in: offset..<offset+count))
        offset += count
        return result
    }
    
    mutating func decodeBigInt() throws -> Data {
        // SSH mpint format: length-prefixed data
        let mpintData = try decodeData()
        
        // SSH mpint format allows for proper sign handling
        // If the data is empty, return empty data (represents 0)
        if mpintData.isEmpty {
            return Data()
        }
        
        // Remove leading zeros to match OpenSSH behavior
        // OpenSSH's sshbuf_get_bignum2_bytes_direct trims leading zeros,
        // but we need to be careful: for ECDSA keys, we might legitimately 
        // have multiple leading zeros that are part of the key value
        //
        // The SSH bigint format adds ONE leading 0x00 if the high bit is set.
        // So we should strip leading zeros, but preserve the semantic value.
        var startIndex = 0
        while startIndex < mpintData.count && mpintData[startIndex] == 0 {
            startIndex += 1
        }
        
        // If all bytes were zeros, return empty data (represents 0)
        if startIndex == mpintData.count {
            return Data()
        }
        
        let result = mpintData.suffix(from: startIndex)
        return Data(result)
    }
}