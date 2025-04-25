// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "boringtun",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "boringtun",
            targets: ["boringtun"])
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        //        .plugin(name: "CargoBoringtun", capability: .command(intent: .custom(verb: "cargo", description: "builds boringtun"), permissions: [.writeToPackageDirectory(reason: "Otherwise it does not build")])),
        .plugin(
            name: "CargoBoringtun",
            capability: .buildTool()),

        .target(
            name: "boringtun",
            publicHeadersPath: "boringrun/src/",
            linkerSettings: [.linkedLibrary("boringtun")]
        ),
        //        .testTarget(
        //            name: "boringtunTests",
        //            dependencies: ["boringtun"],
        //            linkerSettings: [.linkedLibrary("boringtun")]
        //        ),
    ]
)
