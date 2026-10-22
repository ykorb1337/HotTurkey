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
guard arguments.count==5,arguments[1]=="--audit",arguments[3]=="--requirement",let token=Data(base64Encoded:arguments[2]),token.count==32 else { report(["ok":false,"error":"Invalid arguments"],2) }
var requirement:SecRequirement?
var result=SecRequirementCreateWithString(arguments[4] as CFString,flags,&requirement)
guard result==errSecSuccess,let requirement else { report(["ok":false,"stage":"requirement","status":result],1) }
var code:SecCode?
// The kernel audit token includes the PID incarnation, avoiding PID reuse.
let attributes=[kSecGuestAttributeAudit as String:token] as CFDictionary
result=SecCodeCopyGuestWithAttributes(nil,attributes,flags,&code)
guard result==errSecSuccess,let code else { report(["ok":false,"stage":"peer","status":result],1) }
result=SecCodeCheckValidity(code,flags,requirement)
report(["ok":result==errSecSuccess,"status":result],result==errSecSuccess ? 0 : 1)
