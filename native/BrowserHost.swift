// Protected Native Messaging transport. Browser identity comes from the live
// parent code and protected configuration, never extension JSON.
import Foundation
import Security
import Darwin

struct BrowserBinding {
    let name:String
    let requirement:SecRequirement
    let origins:Set<String>
}

func bindings(_ path:String) throws -> [BrowserBinding] {
    let manager=FileManager.default
    #if !QA
    var current=URL(fileURLWithPath:path)
    while true {
        let attributes=try manager.attributesOfItem(atPath:current.path)
        guard attributes[.type] as? FileAttributeType != .typeSymbolicLink,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value==0,
              ((attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0)&0o022==0 else { throw BridgeError.identity }
        if current.path=="/" { break };current.deleteLastPathComponent()
    }
    #endif
    let attributes=try manager.attributesOfItem(atPath:path)
    guard attributes[.type] as? FileAttributeType == .typeRegular,
          (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 65536 else { throw BridgeError.invalid }
    let data=try Data(contentsOf:URL(fileURLWithPath:path))
    guard let config=try JSONSerialization.jsonObject(with:data) as? [String:Any],Set(config.keys)==Set(["version","browsers"]),
          config["version"] as? Int==1,let choices=config["browsers"] as? [String:[String:Any]],!choices.isEmpty,choices.count<=6 else { throw BridgeError.invalid }
    var result=[BrowserBinding]()
    for (name,value) in choices {
        guard ["Edge","Chrome","Firefox","Brave","Opera","Vivaldi"].contains(name),Set(value.keys)==Set(["requirement","origins"]),
              let text=value["requirement"] as? String,text.utf8.count<=4096,let origins=value["origins"] as? [String],
              !origins.isEmpty,origins.count<=32,origins.allSatisfy({ !$0.isEmpty && $0.utf8.count<=256 }) else { throw BridgeError.invalid }
        var requirement:SecRequirement?
        guard SecRequirementCreateWithString(text as CFString,SecCSFlags(rawValue:0),&requirement)==errSecSuccess,
              let requirement else { throw BridgeError.invalid }
        result.append(BrowserBinding(name:name,requirement:requirement,origins:Set(origins)))
    }
    return result
}

func parentIdentity(_ pid:pid_t) throws -> proc_bsdinfo {
    var info=proc_bsdinfo()
    guard pid>1,getppid()==pid,proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,Int32(MemoryLayout<proc_bsdinfo>.size))==MemoryLayout<proc_bsdinfo>.size,
          info.pbi_ruid==getuid(),info.pbi_uid==getuid(),info.pbi_svuid==getuid() else { throw BridgeError.identity }
    return info
}

func parentBinding(_ pid:pid_t,_ expected:proc_bsdinfo,_ choices:[BrowserBinding],_ origins:[String]) throws -> BrowserBinding {
    let info=try parentIdentity(pid)
    guard info.pbi_start_tvsec==expected.pbi_start_tvsec,info.pbi_start_tvusec==expected.pbi_start_tvusec else { throw BridgeError.identity }
    var code:SecCode?
    guard SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid as String:pid] as CFDictionary,SecCSFlags(rawValue:0),&code)==errSecSuccess,let code else { throw BridgeError.identity }
    let matches=choices.filter { value in
        let origin=value.name=="Firefox" ? (origins.count==2 ? origins[1]:""):(origins.count==1 ? origins[0]:"")
        return value.origins.contains(origin) && SecCodeCheckValidity(code,SecCSFlags(rawValue:0),value.requirement)==errSecSuccess
    }
    guard matches.count==1,getppid()==pid else { throw BridgeError.identity }
    _ = try parentIdentity(pid)
    return matches[0]
}

func pipeRead(_ count:Int,_ seconds:UInt64) throws -> Data? {
    let deadline=DispatchTime.now().uptimeNanoseconds+seconds*1_000_000_000
    var result=Data()
    while result.count<count {
        try ready(STDIN_FILENO,Int16(POLLIN),deadline)
        var bytes=[UInt8](repeating:0,count:min(65536,count-result.count))
        let amount=read(STDIN_FILENO,&bytes,bytes.count)
        if amount==0 { if result.isEmpty { return nil };throw BridgeError.invalid }
        if amount<0 && [EINTR,EAGAIN].contains(errno) { continue }
        guard amount>0 else { throw BridgeError.transport }
        result.append(contentsOf:bytes.prefix(amount))
    }
    return result
}

func pipeReply(_ value:[String:Any]) throws {
    let data=try JSONSerialization.data(withJSONObject:value)
    guard data.count<=maximumFrame else { throw BridgeError.invalid }
    var length=UInt32(data.count).littleEndian
    var frame=Data(bytes:&length,count:4);frame.append(data)
    let deadline=DispatchTime.now().uptimeNanoseconds+timeoutNanoseconds
    try frame.withUnsafeBytes { bytes in
        var offset=0
        while offset<bytes.count {
            try ready(STDOUT_FILENO,Int16(POLLOUT),deadline)
            let count=write(STDOUT_FILENO,bytes.baseAddress!.advanced(by:offset),bytes.count-offset)
            if count<0 && [EINTR,EAGAIN].contains(errno) { continue }
            guard count>0 else { throw BridgeError.transport };offset+=count
        }
    }
}

@main
struct BrowserHostMain {
    static func main() {
        signal(SIGPIPE,SIG_IGN)
        do {
            guard getuid()>=500,geteuid()==getuid() else { throw BridgeError.identity }
            for fd in [STDIN_FILENO,STDOUT_FILENO] {
                let flags=fcntl(fd,F_GETFL)
                guard flags>=0,fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0 else { throw BridgeError.transport }
            }
            var config="/Library/PrivilegedHelperTools/local.hotturkey/browsers.json"
            var path="/private/var/run/local.hotturkey/control.sock",uid:uid_t=0
            var origins=Array(CommandLine.arguments.dropFirst())
            #if QA
            guard origins.count>=4,let expected=uid_t(origins[2]) else { throw BridgeError.invalid }
            config=origins[0];path=origins[1];uid=expected;origins=Array(origins.dropFirst(3))
            #endif
            guard (1...2).contains(origins.count) else { throw BridgeError.invalid }
            let choices=try bindings(config),pid=getppid(),parent=try parentIdentity(pid)
            let binding=try parentBinding(pid,parent,choices,origins)
            let channel=UUID().uuidString.replacingOccurrences(of:"-",with:"")+UUID().uuidString.replacingOccurrences(of:"-",with:"")
            var sequence=0
            while let header=try pipeRead(4,120) {
                let count=header.enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element)<<UInt32($1.offset*8) }
                guard count>0,count<=maximumDocument,let body=try pipeRead(Int(count),5),
                      var message=try JSONSerialization.jsonObject(with:body) as? [String:Any] else { throw BridgeError.invalid }
                let supportsDocuments=(message.removeValue(forKey:"document_protocol") as? Int)==1
                let current=try parentBinding(pid,parent,choices,origins)
                guard current.name==binding.name else { throw BridgeError.identity }
                sequence+=1
                var envelope:[String:Any]=["op":"browser-request","data":[
                    "browser":binding.name,"parent_pid":Int(pid),"parent_start_sec":parent.pbi_start_tvsec,
                    "parent_start_usec":parent.pbi_start_tvusec,"channel":channel,"sequence":sequence,"message":message]]
                if message["op"] as? String=="document-read" { envelope=["op":"document-read","data":message["data"] ?? [:]] }
                let payload=try JSONSerialization.data(withJSONObject:envelope)
                do {
                    let response=try documentRequest(payload,path:path,serverUID:uid,resolve:false,beforeEach:{
                        _ = try parentBinding(pid,parent,choices,origins)
                    })
                    guard let value=try JSONSerialization.jsonObject(with:response) as? [String:Any] else { throw BridgeError.invalid }
                    if value["ok"] as? Bool==true,let result=value["result"] as? [String:Any] {
                        if !supportsDocuments,let meta=result["__hotturkey_document__"] as? [String:Any],let token=meta["id"] as? String {
                            let cancel=try JSONSerialization.data(withJSONObject:["op":"document-cancel","data":["id":token]])
                            _ = try request(cancel,path:path,serverUID:uid)
                            try pipeReply(["error":"规则列表较大，请重新加载 HotTurkey 扩展以更新通信协议","policy":true])
                        } else { try pipeReply(result) }
                    }
                    else { try pipeReply(["error":value["error"] as? String ?? "请求未通过验证","policy":true]) }
                } catch { try pipeReply(["error":"HotTurkey 受保护后台未连接"]) }
            }
        } catch { exit(1) }
    }
}
