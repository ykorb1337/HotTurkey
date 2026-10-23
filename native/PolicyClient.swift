import Foundation
import Darwin

@main
struct PolicyClientMain {
    static func main() {
        do {
            var path="/private/var/run/local.hotturkey/control.sock"
            var serverUID:uid_t=0
            #if QA
            guard CommandLine.arguments.count==3,let expectedUID=uid_t(CommandLine.arguments[2]) else { throw BridgeError.invalid }
            path=CommandLine.arguments[1];serverUID=expectedUID
            #else
            guard CommandLine.arguments.count==1 else { throw BridgeError.invalid }
            #endif
            // Read once per process, bounded even if a caller streams oversized input.
            var payload=Data()
            while true {
                let part=FileHandle.standardInput.readData(ofLength:min(65536,maximumDocument+1-payload.count))
                if part.isEmpty { break }
                payload.append(part)
                guard payload.count<=maximumDocument else { throw BridgeError.invalid }
            }
            let response=try documentRequest(payload,path:path,serverUID:serverUID)
            FileHandle.standardOutput.write(response);FileHandle.standardOutput.write(Data([10]))
        } catch {
            // The caller receives neither credentials nor filesystem details in errors.
            FileHandle.standardOutput.write(Data("{\"ok\":false,\"error\":\"本地策略服务连接或身份验证失败\"}\n".utf8))
            exit(1)
        }
    }
}
