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
        // Use `Span` to avoid allocating an intermediate 4‑byte Data slice
        // and an extra bounds check performed by `subdata(in:)`. This keeps
        // the read branch‑predictable and inlinable while maintaining the
        // existing big‑endian semantics.
        let span = data.span
        guard offset + 4 <= span.count else { throw SSHKeyError.invalidKeyData }
        let value = span.readUInt32BigEndian(at: offset)
        offset += 4
        return value
    }
    
    mutating func decodeData() throws -> Data {
        let length = try decodeUInt32()
        let len = Int(length)
        let end = offset + len
        guard end <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        if len == 0 {
            return Data()
        }
        let tt = data.span

        // Avoid subdata(in:) which may trap in debug builds when backed by
        // certain Foundation storage kinds even if the range is checked.
        // Copy directly from the underlying contiguous buffer instead.
        let result: Data = data.withUnsafeBytes { rawBuf in
            precondition(rawBuf.count >= end)
            let base = rawBuf.baseAddress!.advanced(by: offset)
            return Data(bytes: base, count: len)
        }
        offset = end
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
        let end = offset + count
        guard end <= data.count else {
            throw SSHKeyError.invalidKeyData
        }
        if count == 0 { return [] }

        let result: [UInt8] = data.withUnsafeBytes { rawBuf in
            precondition(rawBuf.count >= end)
            let base = rawBuf.bindMemory(to: UInt8.self)
            let startPtr = base.baseAddress!.advanced(by: offset)
            return Array(UnsafeBufferPointer(start: startPtr, count: count))
        }
        offset = end
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
