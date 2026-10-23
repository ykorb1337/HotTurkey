// Bounded native transport shared by the management and session clients.
// Each entry point fixes its own production socket and expected server UID.
import Foundation
import Darwin
import CryptoKit

let maximumFrame=1024*1024
let maximumDocument=64*1024*1024
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

func object(_ data:Data) throws -> [String:Any] {
    guard let value=try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw BridgeError.invalid }
    return value
}

// Uploads execute only after complete integrity verification. Responses stay
// framed; the stdio client resolves them, while Native Messaging resolves at
// the extension boundary to preserve the browser's one-MiB response limit.
func documentRequest(_ payload:Data,path:String,serverUID:uid_t,resolve:Bool=true,beforeEach:() throws -> Void={}) throws -> Data {
    guard payload.count<=maximumDocument else { throw BridgeError.invalid }
    let original=try object(payload),session=original["session"] as? String ?? ""
    func exchange(_ value:[String:Any]) throws -> Data {
        try beforeEach()
        return try request(JSONSerialization.data(withJSONObject:value),path:path,serverUID:serverUID)
    }
    var response:Data
    if payload.count<=maximumFrame {
        try beforeEach();response=try request(payload,path:path,serverUID:serverUID)
    } else {
        guard let operation=original["op"] as? String else { throw BridgeError.invalid }
        let hash=SHA256.hash(data:payload).map { String(format:"%02x",$0) }.joined()
        let start=try exchange(["op":"document-start","session":session,"data":["operation":operation,"size":payload.count,"sha256":hash]])
        let value=try object(start)
        guard value["ok"] as? Bool==true else { return start }
        guard let info=value["result"] as? [String:Any],let token=info["id"] as? String,token.count<=128,
              let chunk=info["chunk_size"] as? Int,(1...262144).contains(chunk) else { throw BridgeError.invalid }
        var offset=0
        while offset<payload.count {
            let end=min(offset+chunk,payload.count)
            let part=try exchange(["op":"document-chunk","session":session,"data":["id":token,"offset":offset,"data":payload[offset..<end].base64EncodedString()]])
            let answer=try object(part)
            guard answer["ok"] as? Bool==true else { return part }
            guard let result=answer["result"] as? [String:Any],result["next"] as? Int==end else { throw BridgeError.invalid }
            offset=end
        }
        response=try exchange(["op":"document-finish","session":session,"data":["id":token]])
    }
    guard resolve else { return response }
    let first=try object(response)
    guard first["ok"] as? Bool==true,let page=first["result"] as? [String:Any],page["__hotturkey_document__"] != nil else { return response }
    guard let meta=page["__hotturkey_document__"] as? [String:Any],let token=meta["id"] as? String,token.count<=128,
          let size=meta["size"] as? Int,(1...maximumDocument).contains(size),let hash=meta["sha256"] as? String,hash.count==64 else { throw BridgeError.invalid }
    var current=page,bytes=Data()
    while true {
        guard let same=current["__hotturkey_document__"] as? [String:Any],same["id"] as? String==token,
              same["sha256"] as? String==hash,same["size"] as? Int==size,current["offset"] as? Int==bytes.count,
              let encoded=current["data"] as? String,let part=Data(base64Encoded:encoded),!part.isEmpty,
              part.count<=262144,bytes.count+part.count<=size else { throw BridgeError.invalid }
        bytes.append(part)
        if current["next"] is NSNull { guard bytes.count==size else { throw BridgeError.invalid };break }
        guard let next=current["next"] as? Int,next==bytes.count,next<size else { throw BridgeError.invalid }
        let answer=try exchange(["op":"document-read","session":session,"data":["id":token,"offset":next]])
        let value=try object(answer)
        guard value["ok"] as? Bool==true else { return answer }
        guard let nextPage=value["result"] as? [String:Any] else { throw BridgeError.invalid };current=nextPage
    }
    guard SHA256.hash(data:bytes).map({ String(format:"%02x",$0) }).joined()==hash else { throw BridgeError.invalid }
    let result=try JSONSerialization.jsonObject(with:bytes,options:[.fragmentsAllowed])
    return try JSONSerialization.data(withJSONObject:["ok":true,"result":result],options:[.withoutEscapingSlashes])
}
