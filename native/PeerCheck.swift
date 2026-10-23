import Foundation
import Security

func report(_ value:[String:Any],_ status:Int32=0)->Never {
    if let data=try? JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]) {
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
    }
    exit(status)
}
let arguments=CommandLine.arguments
let flags=SecCSFlags(rawValue:0)
if arguments.count==3 && arguments[1]=="--describe" {
    var code:SecStaticCode?
    var result=SecStaticCodeCreateWithPath(URL(fileURLWithPath:arguments[2]) as CFURL,flags,&code)
    guard result==errSecSuccess,let code else { report(["ok":false,"status":result],1) }
    result=SecStaticCodeCheckValidity(code,flags,nil)
    guard result==errSecSuccess else { report(["ok":false,"status":result],1) }
    var information:CFDictionary?
    result=SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&information)
    guard result==errSecSuccess,let dictionary=information as? [String:Any],let unique=dictionary[kSecCodeInfoUnique as String] as? Data else { report(["ok":false,"status":result],1) }
    let hash=unique.map { String(format:"%02x",$0) }.joined()
    report(["ok":true,"cdhash":hash,"requirement":"cdhash H\""+hash+"\""])
}
guard arguments.count==5,arguments[1]=="--audit",["--requirement","--roles"].contains(arguments[3]),arguments[4].utf8.count<=4096,let token=Data(base64Encoded:arguments[2]),token.count==32 else { report(["ok":false,"error":"Invalid arguments"],2) }
var code:SecCode?
// The kernel audit token includes the PID incarnation, avoiding PID reuse.
let attributes=[kSecGuestAttributeAudit as String:token] as CFDictionary
var result=SecCodeCopyGuestWithAttributes(nil,attributes,flags,&code)
guard result==errSecSuccess,let code else { report(["ok":false,"stage":"peer","status":result],1) }
if arguments[3]=="--roles" {
    guard let encoded=arguments[4].data(using:.utf8),let choices=(try? JSONSerialization.jsonObject(with:encoded)) as? [String:String],Set(choices.keys)==Set(["client","session"]),Set(choices.values).count==2 else { report(["ok":false,"stage":"roles"],2) }
    var matched=[String]()
    for (role,text) in choices {
        var candidate:SecRequirement?
        let valid=SecRequirementCreateWithString(text as CFString,flags,&candidate)
        guard valid==errSecSuccess,let candidate else { report(["ok":false,"stage":"requirement"],1) }
        if SecCodeCheckValidity(code,flags,candidate)==errSecSuccess { matched.append(role) }
    }
    guard matched.count==1 else { report(["ok":false,"stage":"roles"],1) }
    report(["ok":true,"role":matched[0]])
}
var requirement:SecRequirement?
result=SecRequirementCreateWithString(arguments[4] as CFString,flags,&requirement)
guard result==errSecSuccess,let requirement else { report(["ok":false,"stage":"requirement","status":result],1) }
result=SecCodeCheckValidity(code,flags,requirement)
report(["ok":result==errSecSuccess,"status":result],result==errSecSuccess ? 0 : 1)
