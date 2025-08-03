import Foundation

struct BubbleBabble {
    private static let vowels = "aeiouy"
    private static let consonants = "bcdfghklmnprstvzx"
    
    static func encode(_ data: Data) -> String {
        let dgst_raw = Array(data)
        let dgst_raw_len = dgst_raw.count
        var seed: UInt32 = 1
        let rounds = (dgst_raw_len / 2) + 1
        var retval = "x"
        
        for i in 0..<rounds {
            if (i + 1 < rounds) || (dgst_raw_len % 2 != 0) {
                let byte1 = (i * 2 < dgst_raw_len) ? UInt32(dgst_raw[2 * i]) : 0
                
                let idx0 = ((((byte1) >> 6) & 3) + seed) % 6
                let idx1 = ((byte1) >> 2) & 15
                let idx2 = (((byte1) & 3) + (seed / 6)) % 6
                
                let vowelArray = Array(vowels)
                let consonantArray = Array(consonants)
                
                retval.append(vowelArray[Int(idx0)])
                retval.append(consonantArray[Int(idx1)])
                retval.append(vowelArray[Int(idx2)])
                
                if (i + 1) < rounds {
                    let byte2 = ((2 * i) + 1 < dgst_raw_len) ? UInt32(dgst_raw[(2 * i) + 1]) : 0
                    
                    let idx3 = ((byte2) >> 4) & 15
                    let idx4 = ((byte2)) & 15
                    
                    retval.append(consonantArray[Int(idx3)])
                    retval.append("-")
                    retval.append(consonantArray[Int(idx4)])
                    
                    seed = ((seed * 5) + ((byte1) * 7) + (byte2)) % 36
                }
            } else {
                let idx0 = seed % 6
                let idx1 = 16
                let idx2 = seed / 6
                
                let vowelArray = Array(vowels)
                let consonantArray = Array(consonants)
                
                retval.append(vowelArray[Int(idx0)])
                retval.append(consonantArray[Int(idx1)])
                retval.append(vowelArray[Int(idx2)])
            }
        }
        
        retval.append("x")
        return retval
    }
}