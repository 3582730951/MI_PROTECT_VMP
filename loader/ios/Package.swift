// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VmpLoaderIOS",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "VmpLoaderIOS", targets: ["VmpLoaderIOS"]),
    ],
    targets: [
        .target(
            name: "VmpLoaderIOS",
            path: ".",
            exclude: ["README.md"],
            sources: []
        )
    ]
)

// NOT_IMPLEMENTED: placeholder SwiftPM package for iOS loader integration.
