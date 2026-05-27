// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ssh-keychain",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SSHKeychainCore", targets: ["SSHKeychainCore"]),
        .executable(name: "ssh-keychain", targets: ["SSHKeychainCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.13.0"),
    ],
    targets: [
        .target(
            name: "SSHKeychainCore",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
            ],
            path: "Sources/SSHKeychainCore"
        ),
        .executableTarget(
            name: "SSHKeychainCLI",
            dependencies: [
                "SSHKeychainCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/ssh-keychain"
        ),
        .testTarget(
            name: "SSHKeychainCoreTests",
            dependencies: ["SSHKeychainCore"],
            path: "Tests/SSHKeychainCoreTests"
        ),
    ]
)
