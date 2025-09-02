import Foundation
import Crypto

extension Data {
    @inlinable
    func sha512Data() -> Data {
        let digest = SHA512.hash(data: self)
        return Data(digest)
    }
}