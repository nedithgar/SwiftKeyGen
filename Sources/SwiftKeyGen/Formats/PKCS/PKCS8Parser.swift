import Foundation

/// Minimal parser for encrypted PKCS#8 (ENCRYPTED PRIVATE KEY) supporting
/// the subset we emit: PBES2 { PBKDF2(HMAC-SHA1), AES-128-CBC }.
///
/// This is intentionally narrow – it validates structure and extracts the
/// encrypted payload + PBKDF2 parameters for negative testing and future
/// decryption support. Full decryption is not implemented yet.
struct PKCS8Parser {
    struct ParsedEncryptedPrivateKeyInfo {
        let salt: Data
        let iterations: Int
        let keyLength: Int?
        let iv: Data
        let cipher: String
        let prf: String
        let encryptedData: Data
    }
    
    enum ParserError: Error {
        case invalidPEMHeader
        case base64DecodeFailed
        case asn1Truncated
        case unexpectedTag(String)
        case unsupportedAlgorithm(String)
        case invalidPBES2Parameters
        case invalidPBKDF2Parameters
    }
    
    static func parseEncryptedPrivateKeyInfo(pem: String) throws -> ParsedEncryptedPrivateKeyInfo {
        guard pem.contains("BEGIN ENCRYPTED PRIVATE KEY") else { throw ParserError.invalidPEMHeader }
        // Extract base64 body
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") }
        let b64 = lines.joined()
        guard let der = Data(base64Encoded: b64) else { throw ParserError.base64DecodeFailed }
        var cursor = DERCursor(data: der)
        let top = try cursor.readSequence()
        var topCursor = DERCursor(data: top)
        let algId = try topCursor.readSequence()
        let encryptedOctet = try topCursor.readOctetString()
        // AlgorithmIdentifier = OID + params
        var algCursor = DERCursor(data: algId)
        let algOid = try algCursor.readOID()
        // PBES2 OID 1.2.840.113549.1.5.13
        guard algOid == OID.pbes2 else { throw ParserError.unsupportedAlgorithm(algOid.description) }
        let pbes2Params = try algCursor.readSequence()
        var pbes2Cursor = DERCursor(data: pbes2Params)
        // keyDerivationFunc (sequence)
        let kdfSeq = try pbes2Cursor.readSequence()
        var kdfCursor = DERCursor(data: kdfSeq)
        let kdfOid = try kdfCursor.readOID()
        guard kdfOid == OID.pbkdf2 else { throw ParserError.unsupportedAlgorithm(kdfOid.description) }
        // PBKDF2 params sequence
        let pbkdf2Params = try kdfCursor.readSequence()
        var pbkdf2Cursor = DERCursor(data: pbkdf2Params)
        let salt = try pbkdf2Cursor.readOctetString()
        let iterations = try pbkdf2Cursor.readInteger()
        var keyLength: Int? = nil
        if pbkdf2Cursor.hasRemaining, pbkdf2Cursor.peekTag() == 0x02 { // INTEGER key length
            keyLength = try pbkdf2Cursor.readInteger()
        }
        var prf = "hmacWithSHA1" // default
        if pbkdf2Cursor.hasRemaining { // PRF sequence
            let prfSeq = try pbkdf2Cursor.readSequence()
            var prfCursor = DERCursor(data: prfSeq)
            let prfOid = try prfCursor.readOID()
            prf = prfOid.description
        }
        // encryptionScheme
        let encScheme = try pbes2Cursor.readSequence()
        var encCursor = DERCursor(data: encScheme)
        let encOid = try encCursor.readOID()
        // AES-128-CBC OID 2.16.840.1.101.3.4.1.2
        guard encOid == OID.aes128cbc else { throw ParserError.unsupportedAlgorithm(encOid.description) }
        let iv = try encCursor.readOctetString()
        // Validate trailing bytes consumed
        guard !topCursor.hasRemaining else { throw ParserError.invalidPBES2Parameters }
        return ParsedEncryptedPrivateKeyInfo(
            salt: salt,
            iterations: iterations,
            keyLength: keyLength,
            iv: iv,
            cipher: "aes-128-cbc",
            prf: prf,
            encryptedData: encryptedOctet
        )
    }
}

// MARK: - Minimal DER Reader
fileprivate struct DERCursor {
    private let data: Data
    private(set) var offset: Int = 0
    init(data: Data) { self.data = data }
    var hasRemaining: Bool { offset < data.count }
    mutating func readByte() throws -> UInt8 {
        guard offset < data.count else { throw PKCS8Parser.ParserError.asn1Truncated }
        let b = data[offset]; offset += 1; return b
    }
    mutating func readLength() throws -> Int {
        let first = try readByte()
        if first & 0x80 == 0 { return Int(first) }
        let count = Int(first & 0x7F)
        guard count > 0 && count <= 4 else { throw PKCS8Parser.ParserError.asn1Truncated }
        var value = 0
        for _ in 0..<count { value = (value << 8) | Int(try readByte()) }
        return value
    }
    mutating func readTLV(expectedTag: UInt8) throws -> Data {
        let tag = try readByte()
        guard tag == expectedTag else { throw PKCS8Parser.ParserError.unexpectedTag(String(format: "0x%02X", tag)) }
        let len = try readLength()
        guard offset + len <= data.count else { throw PKCS8Parser.ParserError.asn1Truncated }
        let slice = data.subdata(in: offset..<(offset+len))
        offset += len
        return slice
    }
    mutating func readSequence() throws -> Data { try readTLV(expectedTag: 0x30) }
    mutating func readOctetString() throws -> Data { try readTLV(expectedTag: 0x04) }
    mutating func readOID() throws -> OID {
        let raw = try readTLV(expectedTag: 0x06)
        return OID(raw: raw)
    }
    mutating func readInteger() throws -> Int {
        let raw = try readTLV(expectedTag: 0x02)
        var value = 0
        for b in raw { value = (value << 8) | Int(b) }
        return value
    }
    func peekTag() -> UInt8? { offset < data.count ? data[offset] : nil }
}

fileprivate struct OID: Equatable {
    let raw: Data
    static let pbes2 = OID(raw: Data([0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0D]))
    static let pbkdf2 = OID(raw: Data([0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C]))
    static let aes128cbc = OID(raw: Data([0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02]))
    var description: String {
        // Not decoding fully; provide hex for unsupported message clarity
        return raw.map { String(format: "%02X", $0) }.joined(separator: ".")
    }
}
