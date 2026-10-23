// Protected process scanner/executor. It reads no policy or user-supplied paths.
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#define MAX_PIDS 32768
#define MAX_FRAME (4 * 1024 * 1024)
#define MAX_KILLS 8192
static unsigned char epoch[32];
static BOOL badFrame=NO;

static BOOL integer(id value, unsigned long long high) {
    if (![value isKindOfClass:[NSNumber class]] || CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID()) return NO;
    double number=[value doubleValue];
    return isfinite(number) && number>=0 && number<=high && floor(number)==number;
}
static BOOL same(struct proc_bsdinfo a, struct proc_bsdinfo b) {
    return a.pbi_pid==b.pbi_pid && a.pbi_ruid==b.pbi_ruid && a.pbi_uid==b.pbi_uid && a.pbi_svuid==b.pbi_svuid && a.pbi_start_tvsec==b.pbi_start_tvsec && a.pbi_start_tvusec==b.pbi_start_tvusec;
}
static NSDictionary *inspect(pid_t pid) {
    if (pid<=1 || pid==getpid() || pid==getppid()) return nil;
    struct proc_bsdinfo before={0},after={0};
    if (proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&before,sizeof(before))!=sizeof(before)) return nil;
    // Never terminate a system or privilege-changing process, even for a broad rule.
    if (before.pbi_ruid<500 || before.pbi_uid!=before.pbi_ruid || before.pbi_svuid!=before.pbi_ruid) return nil;
#ifdef HOTTURKEY_QA
    if (before.pbi_ruid!=getuid()) return nil;
#endif
    char path[PROC_PIDPATHINFO_MAXSIZE]={0},again[PROC_PIDPATHINFO_MAXSIZE]={0};
    if (proc_pidpath(pid,path,sizeof(path))<=0 || path[0]!='/') return nil;
    if (proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&after,sizeof(after))!=sizeof(after) || !same(before,after)) return nil;
    if (proc_pidpath(pid,again,sizeof(again))<=0 || strcmp(path,again)) return nil;
    char identity[128];
    int length=snprintf(identity,sizeof(identity),"%d:%u:%u:%u:%llu:%llu:",pid,before.pbi_ruid,before.pbi_uid,before.pbi_svuid,before.pbi_start_tvsec,before.pbi_start_tvusec);
    if (length<=0 || (size_t)length>=sizeof(identity)) return nil;
    NSMutableData *fingerprint=[NSMutableData dataWithBytes:epoch length:sizeof(epoch)];
    [fingerprint appendBytes:identity length:length];[fingerprint appendBytes:path length:strlen(path)];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(fingerprint.bytes,(CC_LONG)fingerprint.length,digest);
    NSMutableString *hex=[NSMutableString stringWithCapacity:64];
    for (size_t i=0;i<sizeof(digest);i++) [hex appendFormat:@"%02x",digest[i]];
    NSString *executable=[[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];
    if (!executable) return nil;
    NSString *application=executable.lastPathComponent,*bundle=@"",*bundlePath=executable;
    NSString *parent=executable.stringByDeletingLastPathComponent;
    while (parent.length>1) {
        if ([parent.pathExtension isEqualToString:@"app"]) {
            bundlePath=parent;application=parent.lastPathComponent.stringByDeletingPathExtension;
            NSString *ident=[NSBundle bundleWithPath:parent].bundleIdentifier;
            if (ident && ident.length<=1024) bundle=ident;
            break;
        }
        parent=parent.stringByDeletingLastPathComponent;
    }
    return @{@"pid":@(pid),@"uid":@(before.pbi_ruid),@"identity":hex,@"executable":executable,
             @"path":bundlePath,@"application":application,@"bundle":bundle};
}
static NSArray *scan(void) {
    pid_t *pids=calloc(MAX_PIDS,sizeof(pid_t));
    if (!pids) return nil;
    int bytes=proc_listpids(PROC_ALL_PIDS,0,pids,MAX_PIDS*sizeof(pid_t));
    if (bytes<=0 || (size_t)bytes>=MAX_PIDS*sizeof(pid_t)) { free(pids);return nil; }
    NSMutableArray *apps=[NSMutableArray array];
    for (int i=0;i<bytes/(int)sizeof(pid_t);i++) {
        NSDictionary *process=inspect(pids[i]);if (process) [apps addObject:process];
    }
    free(pids);return apps;
}
static BOOL emit(NSDictionary *value) {
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    if (!data || data.length>MAX_FRAME) return NO;
    return fwrite(data.bytes,1,data.length,stdout)==data.length && fputc('\n',stdout)!=EOF && fflush(stdout)==0;
}
static NSDictionary *readCommand(void) {
    NSMutableData *data=[NSMutableData data];
    for (size_t i=0;i<=MAX_FRAME;i++) {
        int c=fgetc(stdin);if (c==EOF) { badFrame=data.length!=0;return nil; }
        if (c=='\n') {
            id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (![value isKindOfClass:[NSDictionary class]]) { badFrame=YES;return nil; }
            return value;
        }
        unsigned char byte=(unsigned char)c;[data appendBytes:&byte length:1];
    }
    badFrame=YES;return nil;
}
int main(int argc,const char **argv) {
    (void)argv;
    if (argc!=1) { fputs("No command-line options accepted\n",stderr);return 64; }
#ifndef HOTTURKEY_QA
    if (geteuid()!=0 || getuid()!=0) { fputs("Protected executor requires root installation\n",stderr);return 77; }
#else
    if (geteuid()!=getuid() || getuid()<500) return 77;
#endif
    arc4random_buf(epoch,sizeof(epoch));signal(SIGPIPE,SIG_IGN);
    NSArray *results=@[];NSSet *previous=[NSSet set];
    while (true) {
        @autoreleasepool {
            NSArray *apps=scan();
            if (!apps || !emit(@{@"apps":apps,@"front":@{},@"results":results})) return 70;
            NSDictionary *command=readCommand();if (!command) return feof(stdin)&&!badFrame?0:65;
            if (command.count!=1 || ![command[@"kill"] isKindOfClass:[NSArray class]] || [command[@"kill"] count]>MAX_KILLS) return 65;
            for (id item in command[@"kill"]) {
                if (![item isKindOfClass:[NSDictionary class]] || [item count]!=3 || !integer(item[@"pid"],INT_MAX) || !integer(item[@"uid"],UINT_MAX) || ![item[@"identity"] isKindOfClass:[NSString class]] || [item[@"identity"] length]!=64) return 65;
            }
            NSMutableArray *next=[NSMutableArray array];NSMutableSet *current=[NSMutableSet set];
            for (id item in command[@"kill"]) {
                NSNumber *pid=item[@"pid"],*uid=item[@"uid"];NSString *token=item[@"identity"];
                // Re-read kernel UID, start time and executable immediately before signaling.
                NSDictionary *actual=inspect(pid.intValue);
                NSString *outcome=@"stale";int number=0;
                if (actual && [actual[@"uid"] isEqual:uid] && [actual[@"identity"] isEqual:token]) {
                    if ([current containsObject:token]) continue;
                    [current addObject:token];number=[previous containsObject:token]?SIGKILL:SIGTERM;
                    outcome=kill(pid.intValue,number)==0?@"sent":(errno==ESRCH?@"gone":@"denied");
                }
                [next addObject:@{@"pid":pid,@"uid":uid,@"identity":token,@"signal":@(number),@"result":outcome}];
            }
            previous=[current copy];results=[next copy];
        }
        usleep(1000000);
    }
}
