// Reads the local GUI session directly. No stdin, user-selected samples or
// production socket/identity flags are accepted by this signed executable.
import Foundation
import AppKit
import CoreGraphics
import Darwin

func foreground() -> [String:Any] {
    guard let app=NSWorkspace.shared.frontmostApplication else { return [:] }
    let pid=app.processIdentifier
    var before=proc_bsdinfo(),after=proc_bsdinfo()
    let size=Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&before,size)==size,
          before.pbi_ruid==getuid(),before.pbi_uid==getuid(),before.pbi_svuid==getuid() else { return [:] }
    // sys/proc_info.h defines PROC_PIDPATHINFO_MAXSIZE as 4 * MAXPATHLEN;
    // Swift cannot import that compound macro on all supported SDKs.
    var bytes=[CChar](repeating:0,count:4*Int(MAXPATHLEN))
    guard proc_pidpath(pid,&bytes,UInt32(bytes.count))>0,
          proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&after,size)==size,
          before.pbi_start_tvsec==after.pbi_start_tvsec,before.pbi_start_tvusec==after.pbi_start_tvusec,
          before.pbi_ruid==after.pbi_ruid,before.pbi_uid==after.pbi_uid,before.pbi_svuid==after.pbi_svuid else { return [:] }
    return ["front_pid":Int(pid),"front_start_sec":before.pbi_start_tvsec,
            "front_start_usec":before.pbi_start_tvusec,"front_executable":String(cString:bytes)]
}

@main
struct SessionAgentMain {
    static func main() {
        guard getuid()>=500,getuid()==geteuid() else { exit(77) }
        var path="/private/var/run/local.hotturkey/control.sock"
        var serverUID:uid_t=0
        var limit:Int?=nil
        #if QA
        guard CommandLine.arguments.count==4,let uid=uid_t(CommandLine.arguments[2]),
              let count=Int(CommandLine.arguments[3]),(1...120).contains(count) else { exit(64) }
        path=CommandLine.arguments[1];serverUID=uid;limit=count
        #else
        guard CommandLine.arguments.count==1 else { exit(64) }
        #endif
        var eventSequence=0,sequence=0,accepted=0,consoleSamples=0,frontSamples=0
        let desktop=SessionDesktop()
        #if !QA
        let sleepGuard=SleepGuardUI()
        #endif
        let center=NSWorkspace.shared.notificationCenter
        let observers=[NSWorkspace.didWakeNotification,NSWorkspace.sessionDidBecomeActiveNotification].map { name in
            center.addObserver(forName:name,object:nil,queue:.main) { _ in eventSequence+=1 }
        }
        defer { observers.forEach { center.removeObserver($0) } }
        while limit==nil || sequence<limit! {
            autoreleasepool {
                sequence+=1
                let session=CGSessionCopyCurrentDictionary() as? [String:Any]
                let onConsole=(session?[kCGSessionUserIDKey as String] as? NSNumber)?.uint32Value==getuid()
                    && (session?[kCGSessionOnConsoleKey as String] as? Bool)==true
                    && (session?[kCGSessionLoginDoneKey as String] as? Bool)==true
                let idle=[CGEventType.mouseMoved,.keyDown,.leftMouseDown,.rightMouseDown,.otherMouseDown,.scrollWheel]
                    .map { CGEventSource.secondsSinceLastEventType(.combinedSessionState,eventType:$0) }.min() ?? .infinity
                let validIdle=idle.isFinite && idle>=0
                var sample:[String:Any]=["front_pid":0,"front_start_sec":0,"front_start_usec":0,"front_executable":"",
                    "on_console":onConsole && validIdle,"idle_seconds":validIdle ? min(86400,idle):86400,
                    "sample_seq":sequence,"event_seq":eventSequence]
                if onConsole && validIdle {
                    consoleSamples+=1
                    let front=foreground()
                    if !front.isEmpty { frontSamples+=1;sample.merge(front) { _,new in new } }
                }
                if let result=desktop.result { sample["desktop_result"]=result }
                #if !QA
                if let word=sleepGuard.takeWord() { sample["recovery_word"]=word }
                #endif
                if let payload=try? JSONSerialization.data(withJSONObject:["op":"session-sample","data":sample]),
                   let response=try? request(payload,path:path,serverUID:serverUID),
                   let value=(try? JSONSerialization.jsonObject(with:response)) as? [String:Any],value["ok"] as? Bool==true,
                   let result=value["result"] as? [String:Any],result["accepted"] as? Bool==true {
                    accepted+=1;desktop.accepted(result)
                    #if !QA
                    sleepGuard.render(result["sleep_guard"],recovery:result["recovery_result"])
                    #endif
                }
            }
            RunLoop.current.run(until:Date(timeIntervalSinceNow:1))
        }
        #if QA
        let result:[String:Any]=["accepted":accepted,"samples":sequence,"on_console":consoleSamples,"front_present":frontSamples]
        if let data=try? JSONSerialization.data(withJSONObject:result) { FileHandle.standardOutput.write(data) }
        exit(accepted>0 ? 0:1)
        #endif
    }
}
