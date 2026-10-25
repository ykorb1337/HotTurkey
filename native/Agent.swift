import AppKit
import CoreGraphics
import Darwin
import IOKit.pwr_mgt

func emit(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value), let text = String(data: data, encoding: .utf8) {
        print(text); fflush(stdout)
    }
}
final class AgentCommands {
    private var pending=Data()
    init() { let flags=fcntl(STDIN_FILENO,F_GETFL);_ = fcntl(STDIN_FILENO,F_SETFL,flags|O_NONBLOCK) }
    func next()->[String:Any]? {
        let deadline=ProcessInfo.processInfo.systemUptime+10
        while ProcessInfo.processInfo.systemUptime<deadline {
            if let end=pending.firstIndex(of:10) {
                if pending.distance(from:pending.startIndex,to:end)>4*1024*1024 { return nil }
                let line=Data(pending[..<end]);pending.removeSubrange(pending.startIndex...end)
                return (try? JSONSerialization.jsonObject(with:line)) as? [String:Any]
            }
            if pending.count>4*1024*1024 { return nil }
            var descriptor=pollfd(fd:STDIN_FILENO,events:Int16(POLLIN),revents:0)
            if poll(&descriptor,1,0)>0 {
                var bytes=[UInt8](repeating:0,count:8192)
                let count=Darwin.read(STDIN_FILENO,&bytes,bytes.count)
                if count==0 { return nil }
                if count>0 { pending.append(contentsOf:bytes.prefix(count));continue }
                if errno != EAGAIN && errno != EINTR { return nil }
            }
            // Keep the emergency field and its fail-open timeout responsive
            // even if the parent stops producing commands.
            RunLoop.current.run(until:Date(timeIntervalSinceNow:0.05))
        }
        return nil
    }
}
func deviceAction(_ action: String) {
    if action == "lock" {
        if let handle = dlopen("/System/Library/PrivateFrameworks/login.framework/Versions/Current/login", RTLD_LAZY), let symbol = dlsym(handle, "SACLockScreenImmediate") {
            typealias Lock = @convention(c) () -> Void
            unsafeBitCast(symbol, to: Lock.self)()
        } else { fputs("Screen lock API unavailable\n", stderr) }
    } else if action == "sleep" {
        let connection=IOPMFindPowerManagement(mach_port_t(MACH_PORT_NULL))
        guard connection != 0 else { fputs("Sleep service unavailable\n",stderr);return }
        defer { IOServiceClose(connection) }
        if IOPMSleepSystem(connection) != kIOReturnSuccess { fputs("System sleep request failed\n",stderr) }
    } else if action == "logout" || action == "shutdown" {
        let code = action == "logout" ? "tell application \"System Events\" to log out" : "tell application \"System Events\" to shut down"
        let script = NSAppleScript(source: code)
        var error: NSDictionary?
        script?.executeAndReturnError(&error)
        if let error { fputs("Device action failed: \(error)\n", stderr) }
    }
}
// A recovered helper is not a new login or wake event.
@main
struct AgentMain {
static func main() {
var signin = !CommandLine.arguments.contains("--resume")
var previousKills=Set<Int>()
let sleepGuard=SleepGuardUI()
let commands=AgentCommands()
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
        var sample:[String:Any]=["apps":apps,"front":front.map(info) ?? [:],"idle":idle.isFinite ? idle : 0,"signin":signin]
        if let word=sleepGuard.takeWord() { sample["recovery_word"]=word }
        emit(sample)
        signin = false
        guard let command=commands.next() else { exit(0) }
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
        sleepGuard.render(command["sleep_guard"],recovery:command["recovery_result"])
        if let action = command["device"] as? String { deviceAction(action) }
        for notice in command["notifications"] as? [String] ?? [] {
            DistributedNotificationCenter.default().postNotificationName(NSNotification.Name("local.hotturkey.notice"),object:notice,userInfo:nil,deliverImmediately:true)
        }
    }
    RunLoop.current.run(until:Date(timeIntervalSinceNow:1))
}
}
}
