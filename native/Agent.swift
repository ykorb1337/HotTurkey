import AppKit
import CoreGraphics
import Darwin

func emit(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value), let text = String(data: data, encoding: .utf8) {
        print(text); fflush(stdout)
    }
}
func deviceAction(_ action: String) {
    if action == "lock" {
        if let handle = dlopen("/System/Library/PrivateFrameworks/login.framework/Versions/Current/login", RTLD_LAZY), let symbol = dlsym(handle, "SACLockScreenImmediate") {
            typealias Lock = @convention(c) () -> Void
            unsafeBitCast(symbol, to: Lock.self)()
        } else { fputs("Screen lock API unavailable\n", stderr) }
    } else if action == "logout" || action == "shutdown" {
        let code = action == "logout" ? "tell application \"System Events\" to log out" : "tell application \"System Events\" to shut down"
        let script = NSAppleScript(source: code)
        var error: NSDictionary?
        script?.executeAndReturnError(&error)
        if let error { fputs("Device action failed: \(error)\n", stderr) }
    }
}
// A recovered helper is not a new login or wake event.
var signin = !CommandLine.arguments.contains("--resume")
var sleeping = false
var previousKills=Set<Int>()
var executableInfo=[String:[String:String]]()
func executableMetadata(_ executable:String)->[String:String] {
    if let cached=executableInfo[executable] { return cached }
    var url=URL(fileURLWithPath:executable).deletingLastPathComponent()
    var metadata=["application":URL(fileURLWithPath:executable).lastPathComponent,"path":executable,"executable":executable,"bundle":""]
    while url.path != "/" {
        if url.pathExtension=="app" {
            metadata["path"]=url.path
            metadata["application"]=url.deletingPathExtension().lastPathComponent
            metadata["bundle"]=Bundle(url:url)?.bundleIdentifier ?? ""
            break
        }
        url.deleteLastPathComponent()
    }
    if executableInfo.count>2048 { executableInfo.removeAll() }
    executableInfo[executable]=metadata
    return metadata
}
let center = NSWorkspace.shared.notificationCenter
center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: nil) { _ in signin = true }
center.addObserver(forName: NSWorkspace.sessionDidBecomeActiveNotification, object: nil, queue: nil) { _ in signin = true }
while true {
    autoreleasepool {
        let front = NSWorkspace.shared.frontmostApplication
        func info(_ app: NSRunningApplication) -> [String:Any] {
            ["pid":Int(app.processIdentifier), "application":app.localizedName ?? "", "bundle":app.bundleIdentifier ?? "", "path":app.bundleURL?.path ?? app.executableURL?.path ?? "", "executable":app.executableURL?.path ?? "", "launched":app.launchDate?.timeIntervalSince1970 ?? 0]
        }
        var apps = NSWorkspace.shared.runningApplications.filter { !$0.isTerminated }.map(info)
        // Include executable-only applications as well as .app bundles.
        let ps = Process(); let pipe = Pipe()
        ps.executableURL = URL(fileURLWithPath:"/bin/ps")
        ps.arguments = ["-U", String(getuid()), "-o", "pid=,comm="]
        ps.standardOutput = pipe
        if (try? ps.run()) != nil {
            let text = String(data:pipe.fileHandleForReading.readDataToEndOfFile(),encoding:.utf8) ?? ""
            ps.waitUntilExit()
            let known = Set(apps.compactMap { $0["pid"] as? Int })
            for line in text.split(separator:"\n") {
                let parts = line.trimmingCharacters(in:.whitespaces).split(maxSplits:1,whereSeparator:{$0.isWhitespace})
                if parts.count == 2, let pid = Int(parts[0]), !known.contains(pid), pid != Int(getpid()), pid != Int(getppid()) {
                    let path = String(parts[1])
                    var metadata=executableMetadata(path).mapValues { $0 as Any }
                    metadata["pid"]=pid
                    apps.append(metadata)
                }
            }
        }
        let idle = [CGEventType.mouseMoved,.keyDown,.leftMouseDown,.scrollWheel].map { CGEventSource.secondsSinceLastEventType(.combinedSessionState,eventType:$0) }.min() ?? 0
        emit(["apps":apps,"front":front.map(info) ?? [:],"idle":idle.isFinite ? idle : 0,"signin":signin])
        signin = false
        guard let response = readLine(), let data = response.data(using:.utf8), let command = (try? JSONSerialization.jsonObject(with:data)) as? [String:Any] else { exit(0) }
        let requested=command["kill"] as? [Int] ?? []
        for pid in requested {
            if pid <= 1 || pid == Int(getpid()) || pid == Int(getppid()) { continue }
            if previousKills.contains(pid) { _ = kill(pid_t(pid),SIGKILL) }
            else if let app = NSRunningApplication(processIdentifier:pid_t(pid)) {
                if !app.forceTerminate() { _ = kill(pid_t(pid),SIGKILL) }
            }
            else { _ = kill(pid_t(pid),SIGKILL) }
        }
        previousKills=Set(requested)
        if let action = command["device"] as? String { deviceAction(action) }
        for notice in command["notifications"] as? [String] ?? [] {
            DistributedNotificationCenter.default().postNotificationName(NSNotification.Name("local.hotturkey.notice"),object:notice,userInfo:nil,deliverImmediately:true)
        }
    }
    RunLoop.current.run(until:Date(timeIntervalSinceNow:1))
}
