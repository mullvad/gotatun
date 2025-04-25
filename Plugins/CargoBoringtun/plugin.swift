import Foundation
import PackagePlugin

//@main
//struct CargoBoringtun: CommandPlugin {
//
//    func performCommand(
//        context: PluginContext,
//        arguments: [String]
//    ) async throws {
//        let process = Process()
//        process.executableURL = URL(fileURLWithPath: "~/.cargo/bin/cargo".expandingTildeInPath())
//        process.arguments = ["build", "--target", "aarch64-apple-ios"]
//
//        let outputPipe = Pipe()
//        process.standardOutput = outputPipe
//        try process.run()
//        process.waitUntilExit()
//
//        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
//        let output = String(decoding: outputData, as: UTF8.self)
//
//        print(output)
//    }
//}

@main
struct CargoBoringtun: BuildToolPlugin {

    func createBuildCommands(
        context: PackagePlugin.PluginContext, target: any PackagePlugin.Target
    ) async throws -> [PackagePlugin.Command] {
        //        let process = Process()
        //        process.executableURL = URL(fileURLWithPath: "~/.cargo/bin/cargo".expandingTildeInPath())
        //        process.arguments = ["build", "--target", "aarch64-apple-ios"]
        //
        //        let outputPipe = Pipe()
        //        process.standardOutput = outputPipe
        //        try process.run()
        //        process.waitUntilExit()
        //
        //        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        //        let output = String(decoding: outputData, as: UTF8.self)
        //
        //        print(output)
        return [
            .prebuildCommand(
                displayName: "Running cargo",
                executable: URL(
                    fileURLWithPath: "~/.cargo/bin/cargo".expandingTildeInPath()
                ),
                arguments: ["build", "--target", "aarch64-apple-ios"],
                environment: [:],
                outputFilesDirectory: context.pluginWorkDirectoryURL)
        ]
    }
}

extension String {
    func expandingTildeInPath() -> String {
        (self as NSString).expandingTildeInPath
    }
}
