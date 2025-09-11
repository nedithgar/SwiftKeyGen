// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "SwiftKeyGen",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .macCatalyst(.v26),
        .visionOS(.v26)
    ],
    products: [
        .library(
            name: "SwiftKeyGen",
            targets: ["SwiftKeyGen"]),
        .executable(
            name: "swiftkeygen",
            targets: ["SwiftKeyGenCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
    ],
    targets: [
        .target(
            name: "SwiftKeyGen",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "BigInt", package: "BigInt"),
            ]),
        .testTarget(
            name: "SwiftKeyGenTests",
            dependencies: ["SwiftKeyGen"]
        ),
        .executableTarget(
            name: "SwiftKeyGenCLI",
            dependencies: ["SwiftKeyGen"]
        )
    ]
)
