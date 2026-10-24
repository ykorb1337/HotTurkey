// Signed no-window QA app. Only records its arguments outside the sealed app.
import Foundation
import Darwin

guard let path=Bundle.main.object(forInfoDictionaryKey:"FixtureReceipt") as? String,
      let data=try? JSONSerialization.data(withJSONObject:CommandLine.arguments) else { exit(65) }
let descriptor=open(path,O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW,0o600)
guard descriptor>=0 else { exit(74) }
defer { close(descriptor) }
let line=data+Data([10])
let count=line.withUnsafeBytes { write(descriptor,$0.baseAddress,line.count) }
exit(count==line.count ? 0:74)
