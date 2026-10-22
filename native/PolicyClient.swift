// A narrow stdio bridge to the protected policy authority. No path, UID or
// command-line privilege choices exist in the packaged production binary.
import Foundation
import Darwin

let maximumFrame=1024*1024
let timeoutNanoseconds:UInt64=5_000_000_000
enum BridgeError:Error { case invalid, transport, identity }

func ready(_ fd:Int32,_ events:Int16,_ deadline:UInt64) throws {
    while true {
        let now=DispatchTime.now().uptimeNanoseconds
        guard deadline>now else { throw BridgeError.transport }
        let milliseconds=Int32(min(5000,(deadline-now+999_999)/1_000_000))
        var item=pollfd(fd:fd,events:events,revents:0)
        let result=poll(&item,1,milliseconds)
        if result<0 && errno==EINTR { continue }
        guard result>0 else { throw BridgeError.transport }
        if item.revents&events != 0 { return }
        throw BridgeError.transport
    }
}

func writeAll(_ fd:Int32,_ data:Data,_ deadline:UInt64) throws {
    try data.withUnsafeBytes { bytes in
        var offset=0
        while offset<bytes.count {
            try ready(fd,Int16(POLLOUT),deadline)
            let amount=send(fd,bytes.baseAddress!.advanced(by:offset),bytes.count-offset,0)
            if amount<0 && [EINTR,EAGAIN].contains(errno) { continue }
            guard amount>0 else { throw BridgeError.transport }
            offset+=amount
        }
    }
}

func readExact(_ fd:Int32,_ count:Int,_ deadline:UInt64) throws -> Data {
    var data=Data(count:count)
    try data.withUnsafeMutableBytes { bytes in
        var offset=0
        while offset<count {
            try ready(fd,Int16(POLLIN),deadline)
            let amount=recv(fd,bytes.baseAddress!.advanced(by:offset),count-offset,0)
            if amount<0 && [EINTR,EAGAIN].contains(errno) { continue }
            guard amount>0 else { throw BridgeError.transport }
            offset+=amount
        }
    }
    return data
}

func request(_ payload:Data,path:String,serverUID:uid_t) throws -> Data {
    guard !payload.isEmpty,payload.count<=maximumFrame,
          (try JSONSerialization.jsonObject(with:payload)) is [String:Any] else { throw BridgeError.invalid }
    var address=sockaddr_un()
    let pathBytes=Array(path.utf8)+[0]
    guard pathBytes.count<=MemoryLayout.size(ofValue:address.sun_path) else { throw BridgeError.invalid }
    address.sun_len=UInt8(MemoryLayout<sockaddr_un>.size)
    address.sun_family=sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of:&address.sun_path) { $0.copyBytes(from:pathBytes) }
    let fd=socket(AF_UNIX,SOCK_STREAM,0)
    guard fd>=0 else { throw BridgeError.transport }
    defer { close(fd) }
    var noSignal:Int32=1
    guard setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&noSignal,socklen_t(MemoryLayout<Int32>.size))==0,
          fcntl(fd,F_SETFL,O_NONBLOCK)==0 else { throw BridgeError.transport }
    let deadline=DispatchTime.now().uptimeNanoseconds+timeoutNanoseconds
    let connected=withUnsafePointer(to:&address) { pointer in
        pointer.withMemoryRebound(to:sockaddr.self,capacity:1) { connect(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    if connected != 0 {
        guard errno==EINPROGRESS else { throw BridgeError.transport }
        try ready(fd,Int16(POLLOUT),deadline)
        var error:Int32=0
        var size=socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)==0,error==0 else { throw BridgeError.transport }
    }
    // Verify the kernel's server UID before transmitting passwords or sessions.
    var uid:uid_t=0;var gid:gid_t=0
    guard getpeereid(fd,&uid,&gid)==0,uid==serverUID else { throw BridgeError.identity }
    var length=UInt32(payload.count).bigEndian
    var frame=Data(bytes:&length,count:4);frame.append(payload)
    try writeAll(fd,frame,deadline)
    let header=try readExact(fd,4,deadline)
    let count=header.reduce(UInt32(0)) { ($0<<8)|UInt32($1) }
    guard count>0,count<=maximumFrame else { throw BridgeError.invalid }
    let response=try readExact(fd,Int(count),deadline)
    guard (try JSONSerialization.jsonObject(with:response)) is [String:Any] else { throw BridgeError.invalid }
    return response
}

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
        let part=FileHandle.standardInput.readData(ofLength:min(65536,maximumFrame+1-payload.count))
        if part.isEmpty { break }
        payload.append(part)
        guard payload.count<=maximumFrame else { throw BridgeError.invalid }
    }
    let response=try request(payload,path:path,serverUID:serverUID)
    FileHandle.standardOutput.write(response);FileHandle.standardOutput.write(Data([10]))
} catch {
    // The caller receives neither credentials nor filesystem details in errors.
    FileHandle.standardOutput.write(Data("{\"ok\":false,\"error\":\"本地策略服务连接或身份验证失败\"}\n".utf8))
    exit(1)
}
