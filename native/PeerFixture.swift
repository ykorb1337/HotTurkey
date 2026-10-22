// Disposable peer used by the identity integration test; never installed.
import Foundation
import Darwin

guard CommandLine.arguments.count==2 else { exit(2) }
let path=Array(CommandLine.arguments[1].utf8)+[0]
var address=sockaddr_un()
guard path.count<=MemoryLayout.size(ofValue:address.sun_path) else { exit(2) }
address.sun_len=UInt8(MemoryLayout<sockaddr_un>.size)
address.sun_family=sa_family_t(AF_UNIX)
withUnsafeMutableBytes(of:&address.sun_path) { buffer in buffer.copyBytes(from:path) }
let fd=socket(AF_UNIX,SOCK_STREAM,0)
guard fd>=0 else { exit(3) }
let connected=withUnsafePointer(to:&address) { pointer in
    pointer.withMemoryRebound(to:sockaddr.self,capacity:1) { connect(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) }
}
guard connected==0 else { exit(4) }
var byte:UInt8=0
_ = read(fd,&byte,1)
close(fd)
