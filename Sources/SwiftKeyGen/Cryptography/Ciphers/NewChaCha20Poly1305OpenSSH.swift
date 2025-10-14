import Foundation
import BigInt

/// ChaCha20-Poly1305 implementation mirroring OpenSSH's chachapoly cipher.
/// This variant uses a 64-byte key split into a main encryption key (first
/// 32 bytes) and a header key (second 32 bytes). The nonce is an 8-byte packet
/// sequence encoded in little-endian form. Authentication tags are 16 bytes.
enum NewChaCha20Poly1305OpenSSH {
    private static let keyLength = 64
    private static let polyKeyLength = 32
    private static let tagLength = 16

    static func encrypt(
        data: Data,
        key: Data,
        iv: Data,
        aadLength: Int = 0
    ) throws -> Data {
        guard key.count == keyLength else {
            throw SSHKeyError.invalidKeySize(key.count, "ChaCha20-Poly1305 requires a 64-byte key")
        }
        let nonce = try prepareNonce(from: iv)
        let clampedAAD = clampAADLength(aadLength, dataLength: data.count)
        let messageLength = data.count - clampedAAD

        var mainCtx = ChaCha20Core(keyBytes: Array(key.prefix(32)))
        var headerCtx = ChaCha20Core(keyBytes: Array(key.suffix(32)))

        var keystream = [UInt8](repeating: 0, count: 64)
        mainCtx.setNonce(nonce, counter: 0)
        mainCtx.generateKeystream(into: &keystream)
        var polyKey = Array(keystream.prefix(polyKeyLength))

        var output = Data(count: data.count + tagLength)
        output.withUnsafeMutableBytes { destPtr in
            guard let destBase = destPtr.baseAddress else { return }
            data.withUnsafeBytes { srcPtr in
                guard let srcBase = srcPtr.baseAddress else { return }

                if clampedAAD > 0 {
                    headerCtx.setNonce(nonce, counter: 0)
                    let aadInput = UnsafeRawBufferPointer(start: srcBase, count: clampedAAD)
                    var aadOutput = UnsafeMutableRawBufferPointer(start: destBase, count: clampedAAD)
                    headerCtx.xor(input: aadInput, output: &aadOutput)
                }

                if messageLength > 0 {
                    mainCtx.setNonce(nonce, counter: 1)
                    let msgInput = UnsafeRawBufferPointer(
                        start: srcBase.advanced(by: clampedAAD),
                        count: messageLength
                    )
                    var msgOutput = UnsafeMutableRawBufferPointer(
                        start: destBase.advanced(by: clampedAAD),
                        count: messageLength
                    )
                    mainCtx.xor(input: msgInput, output: &msgOutput)
                }
            }
        }

        let ciphertextSlice = output.prefix(data.count)
        let tag = Poly1305.tag(for: Array(ciphertextSlice), key: polyKey)
        output.replaceSubrange(data.count..<output.count, with: tag)

        polyKey.resetBytes()
        keystream.resetBytes()
        return output
    }

    static func decrypt(
        data: Data,
        key: Data,
        iv: Data,
        aadLength: Int = 0
    ) throws -> Data {
        guard data.count >= tagLength else {
            throw SSHKeyError.invalidFormat
        }
        guard key.count == keyLength else {
            throw SSHKeyError.invalidKeySize(key.count, "ChaCha20-Poly1305 requires a 64-byte key")
        }

        let nonce = try prepareNonce(from: iv)
        let ciphertext = data.prefix(data.count - tagLength)
        let receivedTag = Array(data.suffix(tagLength))
        let clampedAAD = clampAADLength(aadLength, dataLength: ciphertext.count)
        let messageLength = ciphertext.count - clampedAAD

        var mainCtx = ChaCha20Core(keyBytes: Array(key.prefix(32)))
        var headerCtx = ChaCha20Core(keyBytes: Array(key.suffix(32)))

        var keystream = [UInt8](repeating: 0, count: 64)
        mainCtx.setNonce(nonce, counter: 0)
        mainCtx.generateKeystream(into: &keystream)
        var polyKey = Array(keystream.prefix(polyKeyLength))

        let expectedTag = Poly1305.tag(for: Array(ciphertext), key: polyKey)
        let tagsMatch = constantTimeEquals(expectedTag, receivedTag)
        polyKey.resetBytes()
        keystream.resetBytes()

        guard tagsMatch else {
            throw SSHKeyError.decryptionFailed
        }

        var plaintext = Data(count: ciphertext.count)
        plaintext.withUnsafeMutableBytes { destPtr in
            guard let destBase = destPtr.baseAddress else { return }
            ciphertext.withUnsafeBytes { srcPtr in
                guard let srcBase = srcPtr.baseAddress else { return }

                if clampedAAD > 0 {
                    headerCtx.setNonce(nonce, counter: 0)
                    let aadInput = UnsafeRawBufferPointer(start: srcBase, count: clampedAAD)
                    var aadOutput = UnsafeMutableRawBufferPointer(start: destBase, count: clampedAAD)
                    headerCtx.xor(input: aadInput, output: &aadOutput)
                }

                if messageLength > 0 {
                    mainCtx.setNonce(nonce, counter: 1)
                    let msgInput = UnsafeRawBufferPointer(
                        start: srcBase.advanced(by: clampedAAD),
                        count: messageLength
                    )
                    var msgOutput = UnsafeMutableRawBufferPointer(
                        start: destBase.advanced(by: clampedAAD),
                        count: messageLength
                    )
                    mainCtx.xor(input: msgInput, output: &msgOutput)
                }
            }
        }

        return plaintext
    }

    private static func clampAADLength(_ requested: Int, dataLength: Int) -> Int {
        if requested <= 0 {
            return 0
        }
        return min(requested, dataLength)
    }

    private static func prepareNonce(from iv: Data) throws -> [UInt8] {
        switch iv.count {
        case 0:
            return [UInt8](repeating: 0, count: 8)
        case 8:
            return Array(iv)
        default:
            throw SSHKeyError.invalidKeySize(iv.count, "ChaCha20-Poly1305 nonce must be 8 bytes")
        }
    }

    private static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        var diff: UInt8 = 0
        for index in 0..<lhs.count {
            diff |= lhs[index] ^ rhs[index]
        }
        return diff == 0
    }

    private struct ChaCha20Core {
        private static let stateWords = 16
        private var state: [UInt32] = Array(repeating: 0, count: stateWords)

        init(keyBytes: [UInt8]) {
            precondition(keyBytes.count == 32)
            state[0] = 0x6170_7865
            state[1] = 0x3320_646e
            state[2] = 0x7962_2d32
            state[3] = 0x6b20_6574

            for index in 0..<8 {
                state[4 + index] = Self.loadUInt32(from: keyBytes, offset: index * 4)
            }
        }

        mutating func setNonce(_ nonce: [UInt8], counter: UInt64) {
            precondition(nonce.count == 8)
            state[12] = UInt32(counter & 0xffff_ffff)
            state[13] = UInt32(counter >> 32)
            state[14] = Self.loadUInt32(from: nonce, offset: 0)
            state[15] = Self.loadUInt32(from: nonce, offset: 4)
        }

        mutating func xor(
            input: UnsafeRawBufferPointer,
            output: inout UnsafeMutableRawBufferPointer
        ) {
            guard let inBase = input.baseAddress, let outBase = output.baseAddress else {
                return
            }

            var remaining = input.count
            var inputPointer = inBase.assumingMemoryBound(to: UInt8.self)
            var outputPointer = outBase.assumingMemoryBound(to: UInt8.self)
            var keystream = [UInt8](repeating: 0, count: 64)

            while remaining > 0 {
                let blockSize = min(remaining, 64)
                generateKeystream(into: &keystream)
                for index in 0..<blockSize {
                    let byte = inputPointer[index]
                    outputPointer[index] = byte ^ keystream[index]
                }
                inputPointer = inputPointer.advanced(by: blockSize)
                outputPointer = outputPointer.advanced(by: blockSize)
                remaining -= blockSize
            }
        }

        mutating func generateKeystream(into buffer: inout [UInt8]) {
            precondition(buffer.count >= 64)

            var workingState = state

            for _ in 0..<10 {
                quarterRound(&workingState, 0, 4, 8, 12)
                quarterRound(&workingState, 1, 5, 9, 13)
                quarterRound(&workingState, 2, 6, 10, 14)
                quarterRound(&workingState, 3, 7, 11, 15)
                quarterRound(&workingState, 0, 5, 10, 15)
                quarterRound(&workingState, 1, 6, 11, 12)
                quarterRound(&workingState, 2, 7, 8, 13)
                quarterRound(&workingState, 3, 4, 9, 14)
            }

            for index in 0..<Self.stateWords {
                workingState[index] = workingState[index] &+ state[index]
            }

            for index in 0..<Self.stateWords {
                let word = workingState[index]
                buffer[index * 4 + 0] = UInt8(truncatingIfNeeded: word & 0xff)
                buffer[index * 4 + 1] = UInt8(truncatingIfNeeded: (word >> 8) & 0xff)
                buffer[index * 4 + 2] = UInt8(truncatingIfNeeded: (word >> 16) & 0xff)
                buffer[index * 4 + 3] = UInt8(truncatingIfNeeded: (word >> 24) & 0xff)
            }

            state[12] = state[12] &+ 1
            if state[12] == 0 {
                state[13] = state[13] &+ 1
            }
        }

        private func rotateLeft(_ value: UInt32, by amount: UInt32) -> UInt32 {
            return (value << amount) | (value >> (32 - amount))
        }

        private mutating func quarterRound(
            _ state: inout [UInt32],
            _ a: Int,
            _ b: Int,
            _ c: Int,
            _ d: Int
        ) {
            state[a] = state[a] &+ state[b]
            state[d] = rotateLeft(state[d] ^ state[a], by: 16)
            state[c] = state[c] &+ state[d]
            state[b] = rotateLeft(state[b] ^ state[c], by: 12)
            state[a] = state[a] &+ state[b]
            state[d] = rotateLeft(state[d] ^ state[a], by: 8)
            state[c] = state[c] &+ state[d]
            state[b] = rotateLeft(state[b] ^ state[c], by: 7)
        }

        private static func loadUInt32(from bytes: [UInt8], offset: Int) -> UInt32 {
            let b0 = UInt32(bytes[offset])
            let b1 = UInt32(bytes[offset + 1]) << 8
            let b2 = UInt32(bytes[offset + 2]) << 16
            let b3 = UInt32(bytes[offset + 3]) << 24
            return b0 | b1 | b2 | b3
        }
    }

    private struct Poly1305 {
        static func tag(for message: [UInt8], key: [UInt8]) -> [UInt8] {
            precondition(key.count == NewChaCha20Poly1305OpenSSH.polyKeyLength)

            var rBytes = Array(key.prefix(16))
            clampR(&rBytes)
            let sBytes = Array(key.suffix(16))

            let r = bigUInt(fromLittleEndian: rBytes)
            let s = bigUInt(fromLittleEndian: sBytes)
            let modulus = (BigUInt(1) << 130) - 5
            var accumulator = BigUInt(0)

            var index = 0
            while index < message.count {
                let blockLength = min(16, message.count - index)
                let blockBytes = Array(message[index..<index + blockLength])
                var blockValue = bigUInt(fromLittleEndian: blockBytes)
                blockValue += BigUInt(1) << (blockLength * 8)

                accumulator += blockValue
                accumulator %= modulus
                accumulator *= r
                accumulator %= modulus

                index += blockLength
            }

            let tagValue = (accumulator + s) % (BigUInt(1) << 128)
            return littleEndianBytes(of: tagValue, count: 16)
        }

        private static func clampR(_ bytes: inout [UInt8]) {
            bytes[3] &= 15
            bytes[7] &= 15
            bytes[11] &= 15
            bytes[15] &= 15
            bytes[4] &= 252
            bytes[8] &= 252
            bytes[12] &= 252
        }

        private static func bigUInt(fromLittleEndian bytes: [UInt8]) -> BigUInt {
            var value = BigUInt(0)
            for (index, byte) in bytes.enumerated() where byte != 0 {
                value += BigUInt(byte) << (index * 8)
            }
            return value
        }

        private static func littleEndianBytes(of value: BigUInt, count: Int) -> [UInt8] {
            var result = [UInt8](repeating: 0, count: count)
            var remaining = value
            for index in 0..<count {
                let byte = UInt8(truncatingIfNeeded: remaining & 0xff)
                result[index] = byte
                remaining >>= 8
            }
            return result
        }
    }
}

private extension Array where Element == UInt8 {
    mutating func resetBytes() {
        for index in indices {
            self[index] = 0
        }
    }
}
