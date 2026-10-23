# Protected policy service: current boundary

Status: experimental foundation, **not installed** by the application or
`scripts/install.py`. The released application still runs only the current
user's service. The source now connects a kernel process executor to the
protected authority, but the released application does not yet provide an
installed system daemon, anti-uninstall protection or verified cross-account
enforcement.

## Implemented

- `PolicyAuthority` owns shared rules and locks, with per-UID usage charges,
  breaks, challenges and statistics. Only the selected local controller account
  can manage policy, and its settings password is checked separately.
- `authority_server.py` serves bounded Unix-socket requests. The kernel supplies
  UID, PID and audit token; client-supplied identity and filesystem fields are
  rejected. A root-selected code requirement is checked before reading a request.
- `HotTurkeyPolicyClient` is a hardened native stdio bridge. Its production
  socket path and expected server UID are fixed. It checks the server's kernel
  UID before sending passwords or session tokens. The separate QA binary has
  test-only path and UID arguments and is excluded from the application bundle.
- `HotTurkeySessionAgent` samples the actual console session, foreground kernel
  PID/start time/executable, and idle state. It has no stdin/sample injection or
  production path/UID overrides. Root-selected distinct code requirements give
  it only the `session-sample` operation; ordinary management clients cannot
  report usage. The shared native transport checks the server UID first.
- `TrustedSessions` verifies foreground information against fresh (at most
  three seconds old) executor inventory belonging to that kernel peer's UID.
  Root measures elapsed time; replay, concurrent agents, stale/idle/off-console
  intervals and unmatched identities do not create activity. Per-account
  foreground allowances/rewards and matching strict background usage are
  accumulated without earning focus from a running background target. Browser
  foreground activity cannot earn web-only rewards without URL integration.
- Login markers use libbsm-decoded kernel audit sessions plus the boot ID,
  persisted in protected state. Restarting an agent does not invent a login.
  Native wake/session-active notifications advance a sequence; repeated or
  reversed samples cannot retrigger it. This is not yet real sleep/wake QA.
- One request per connection, at most eight workers, 1 MiB frames, bounded
  verification and I/O deadlines. Malformed/duplicate JSON keys, non-finite
  numbers, oversized integers and unrecognized operations are rejected. There
  is no arbitrary command execution or management-client usage operation.
- Rule management uses the same lock checks as the current app. Locked rules
  permit atomic target additions, timer extensions and longer text challenges;
  other edits and deletion remain protected.
- `HotTurkeySystemAgent` enumerates processes using libproc kernel information,
  including the real/effective/saved UID, process start time and executable.
  It excludes system accounts, privilege-changing processes and its own parent.
  Each scan produces an executor-epoch identity; every signal rechecks that
  identity and UID rather than accepting a bare PID. The whole command batch is
  validated before any signal is sent. A process still matching on the next
  cycle receives SIGKILL after SIGTERM.
- `SystemExecution` derives account contexts from those kernel samples and
  applies the shared authority's per-account application rules, schedules and
  existing break ledgers. Successful signal acknowledgements drive statistics;
  rejected/stale actions are not reported as successful blocks. RPC exposes no
  process-list, PID-kill or caller-supplied usage operation.
- The protected entry point requires the root-owned executor and starts it
  beside policy RPC. An executor crash, stalled pipe or invalid sample stops
  the authority and removes its socket, allowing an eventual launchd supervisor
  to restart the service instead of leaving a healthy-looking policy-only
  listener. No root supervisor is installed yet.
- Root startup requires an existing root-owned installation, configuration,
  data directory and socket directory with no writable or linked ancestors.
  It refuses an ordinary-user launch. No startup path elevates privileges.
- Shutdown removes only its own socket; a live listener or unrelated file is
  never replaced. Policy clock/storage failures stop the service so an eventual
  supervisor can restart it. Session tokens expire and are not persisted.

The local ad-hoc build pins distinct client and session-agent `cdhash` values.
Protected `authority.json` now requires version 2, `controller_uid`, and
`requirements` with exactly `client` and `session` pinned requirement strings.
There is no existing system installation to migrate; the current installer
does not create this configuration. A release with a Developer ID
will need an upgrade policy and appropriate designated requirement. Code
identity uses Apple's [guest code attributes](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys)
and [SecCodeCopyGuestWithAttributes](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)).

## Isolated verification

```sh
python3 scripts/build.py --qa
python3 tests/integration_authority.py
python3 tests/integration_system_enforcement.py
python3 tests/integration_trusted_sessions.py
```

The test starts an ordinary-user service in a temporary directory and uses the
signed QA native client. It verifies the actual kernel UID/PID, allowed code,
rejection of unapproved code running as the same user, claimed UID rejection,
password authorization, locked additions and preserved locks after restart.
A wrong-UID test server receives no password bytes. No installed rules,
protected system paths, login items or user accounts are changed.

Unit tests use fake account records for controller/noncontroller isolation.
These are not real multi-user macOS integration tests. Proof JSON is generated
under ignored `build/`; the tests are the reproducible public artifact.

The execution integration uses the same native implementation compiled as
`HotTurkeySystemAgentQA`, restricted to the current real UID. That QA binary is
excluded from the application bundle; the production binary refuses ordinary
user launch and accepts no path, UID or other command-line options. Real signed
RPC appends targets to a locked rule and ends only uniquely named test programs.
It verifies SIGTERM, SIGKILL for an ignoring fixture, unrelated processes,
kernel UID/generation rejection, same-PID exec replacement, atomic malformed
batch rejection, executor-crash shutdown and restart with locks preserved.
The integration does not install root files, alter user applications or prove
separate-account execution. Evidence: `build/system-execution-proof.json`.

Process structures and inspection use Apple's
[libproc implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c)
and [proc_info definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h).
Revalidation reduces stale-PID/exec errors; it is not an atomic pidfd-style
kernel handle guarantee.

Session integration runs real signed native agents and the current-UID kernel
scanner with statistics disabled in a temporary database. It verifies distinct
roles, kernel UID/PID/audit-session decoding, passive samples, restart markers,
unsigned caller rejection and no activity sent to a wrong-UID server. Aggregate
console/foreground counts are recorded without application names or paths in
`build/trusted-session-proof.json`. Headless CI may have no console/foreground;
transport success alone does not prove real foreground allowance expiry or
sleep/wake behavior. No installed rules or GUI focus are changed.

## Work still required before system installation

1. Connect policy RPC to desktop, browser bridge and command-line clients with
   complete settings/import/export/statistics support and large-policy paging.
2. Install/supervise the trusted session agents and complete browser heartbeats,
   notifications and authorized device actions. Foreground/idle and native
   login/wake observations now have an isolated trusted path, but real GUI
   allowance expiry, sleep/wake and cross-account session transitions remain
   unverified. Missing agents do not invent activity; supervision and tamper
   recovery must be validated before this becomes a protective system mode.
   Strictness/browser-presence options also still need integration.
3. Provide a reviewed, transactional privileged installer, migration, startup,
   update and lock-aware uninstall path. Current expected paths are
   `/Library/PrivilegedHelperTools/local.hotturkey`,
   `/private/var/db/local.hotturkey` and
   `/private/var/run/local.hotturkey/control.sock`; no files are placed there by
   the current installer.
4. Validate actual separate macOS accounts, login/logout, sleep/wake, crashes,
   tampering, upgrades and recovery, including ordinary-user bypass attempts.
5. Complete distribution signing/notarization. Root/admin recovery remains an
   explicit boundary; no user-space tool can promise protection against an
   administrator who controls the machine.
