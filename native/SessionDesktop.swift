// The authority sends only an opaque login ticket. Paths and arguments never
// come from policy JSON. Production launches the immutable system app only.
import Foundation
import AppKit
import Security
import Darwin

final class SessionDesktop {
    private var lastID:String?
    private var lastOutcome:[String:Any]?
    private(set) var result:[String:Any]?
    private let launch:()->Bool
    init(launch:@escaping()->Bool={ launchSystemDesktop() }) { self.launch=launch }
    func accepted(_ reply:[String:Any]) {
        guard reply["accepted"] as? Bool == true else { return }
        var ticket:String?
        if let value=reply["desktop"] {
            guard let plan=value as? [String:Any],Set(plan.keys)==Set(["id"]),let id=plan["id"] as? String,
                  id.count==64,id.utf8.allSatisfy({ (48...57).contains($0)||(97...102).contains($0) }) else { return }
            ticket=id
        }
        result=nil
        guard let id=ticket else { return }
        if id==lastID { result=lastOutcome;return }
        lastID=id;lastOutcome=["id":id,"ok":launch()];result=lastOutcome
    }
}

func launchSystemDesktop()->Bool {
    return launchDesktop(at:URL(fileURLWithPath:"/Library/PrivilegedHelperTools/local.hotturkey/HotTurkey.app"),owner:0,checkAncestors:true)
}

func launchDesktop(at app:URL,owner:uid_t,checkAncestors:Bool)->Bool {
    let executable=app.appendingPathComponent("Contents/MacOS/HotTurkey")
    // Root owns every production ancestor. QA alone uses an explicitly staged
    // signed fixture; that separate harness is never shipped in the app.
    var current=executable
    while true {
        var info=stat()
        guard lstat(current.path,&info)==0,info.st_uid==owner,(info.st_mode&0o022)==0,
              (info.st_mode&S_IFMT) != S_IFLNK,
              (current==executable ? (info.st_mode&S_IFMT)==S_IFREG : (info.st_mode&S_IFMT)==S_IFDIR) else { return false }
        if current.path=="/" || (!checkAncestors && current==app) { break }
        current.deleteLastPathComponent()
    }
    var metadata=stat()
    guard lstat(app.appendingPathComponent("Contents/Info.plist").path,&metadata)==0,
          metadata.st_uid==owner,(metadata.st_mode&0o022)==0,(metadata.st_mode&S_IFMT)==S_IFREG else { return false }
    guard let bundle=Bundle(url:app),bundle.bundleIdentifier=="local.hotturkey.desktop",
          bundle.object(forInfoDictionaryKey:"HotTurkeySystemMode") as? Bool==true,
          bundle.executableURL?.standardizedFileURL==executable.standardizedFileURL else { return false }
    var code:SecStaticCode?
    let flags=SecCSFlags(rawValue:kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode)
    guard SecStaticCodeCreateWithPath(app as CFURL,SecCSFlags(rawValue:0),&code)==errSecSuccess,
          let code,SecStaticCodeCheckValidity(code,flags,nil)==errSecSuccess else { return false }
    if NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.standardizedFileURL==app.standardizedFileURL && !$0.isTerminated }) { return true }
    let process=Process()
    process.executableURL=executable;process.arguments=["--system","--login"]
    process.currentDirectoryURL=app
    process.environment=["PATH":"/usr/bin:/bin","HOME":FileManager.default.homeDirectoryForCurrentUser.path]
    process.standardInput=FileHandle.nullDevice;process.standardOutput=FileHandle.nullDevice;process.standardError=FileHandle.nullDevice
    do { try process.run();return true } catch { return false }
}
