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
- One request per connection, at most eight workers, 1 MiB frames, bounded
  verification and I/O deadlines. Malformed/duplicate JSON keys, non-finite
  numbers, oversized integers and unrecognized operations are rejected. There
  is no arbitrary command execution or client-reported usage operation.
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

The local ad-hoc build pins a client `cdhash`. A release with a Developer ID
will need an upgrade policy and appropriate designated requirement. Code
identity uses Apple's [guest code attributes](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys)
and [SecCodeCopyGuestWithAttributes](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)).

## Isolated verification

```sh
python3 scripts/build.py --qa
python3 tests/integration_authority.py
python3 tests/integration_system_enforcement.py
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

## Work still required before system installation

1. Connect policy RPC to desktop, browser bridge and command-line clients with
   complete settings/import/export/statistics support and large-policy paging.
2. Connect trusted per-session agents for foreground/idle information, browser
   heartbeats, notifications, login/wake events and authorized device actions.
   The scanner does not invent activity or charge allowances from missing
   session data. Usage-based breaks respect existing ledgers, but system-mode
   activity accumulation is not complete. Strictness/browser-presence options
   also still need system-mode integration and validation.
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
