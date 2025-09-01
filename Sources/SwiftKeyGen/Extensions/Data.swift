import Foundation
import Crypto

extension Data {
    var sha512: Data {
        let digest = SHA512.hash(data: self)
        return Data(digest)
    }
}