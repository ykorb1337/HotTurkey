// Standalone QA harness for the same delivery/parser/launcher implementation.
// No socket, session claims or production installation overrides are exposed.
import Foundation
import Darwin

@main
struct SessionDesktopFixture {
    static func main() throws {
        guard CommandLine.arguments.count==2 else { exit(64) }
        let app=URL(fileURLWithPath:CommandLine.arguments[1])
        let data=FileHandle.standardInput.readDataToEndOfFile()
        guard data.count<=32768,let replies=try JSONSerialization.jsonObject(with:data) as? [[String:Any]] else { exit(65) }
        var launches=0
        let desktop=SessionDesktop(launch:{ launches+=1;return launchDesktop(at:app,owner:getuid(),checkAncestors:false) })
        var answers=[[String:Any]]()
        for reply in replies {
            desktop.accepted(reply)
            answers.append(["launch_calls":launches,"result":desktop.result ?? [:]])
        }
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject:answers))
    }
}
