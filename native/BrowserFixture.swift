// Explicit test parent; never packaged or installed.
import Foundation
guard CommandLine.arguments.count>=6 else { exit(64) }
let child=Process()
child.executableURL=URL(fileURLWithPath:CommandLine.arguments[1])
child.arguments=Array(CommandLine.arguments.dropFirst(2))
child.standardInput=FileHandle.standardInput;child.standardOutput=FileHandle.standardOutput;child.standardError=FileHandle.standardError
do { try child.run();child.waitUntilExit();exit(child.terminationStatus) } catch { exit(1) }
