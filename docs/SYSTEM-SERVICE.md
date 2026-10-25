# Protected policy service: current boundary

Status: experimental foundation, **not installed** by the application or
`scripts/install.py`. The released application still runs only the current
user's service. The source now connects a kernel process executor to the
protected authority, but the released application does not yet provide an
installed system daemon, anti-uninstall protection or verified cross-account
enforcement.

## Implemented

- Scheduled sleep now has a mandatory user-chosen recovery word and a
  30-second console/wake countdown. The kernel executor accepts only a fixed
  sleep action, checks the console UID again immediately before requesting
  sleep and returns a nonce-bound receipt. A successful request does not prove
  the machine slept. QA binaries compile out physical sleep completely.
- Each attested session agent can submit a recovery word only for its kernel
  account. A correct word temporarily releases that account's current device
  episode, including after authority/helper restart. Controller + settings
  authorization is additionally required to stop current shared device plans
  and remove their automatic starts. Other account recovery does not disable
  shared policy. Credentials are salted hashes, omitted from policy exports
  and redacted in snapshots. Device recovery requires no settings password.
- A native recovery surface shows the deadline, accepts the word before and
  after wake, and removes its overlay after five seconds without fresh trusted
  updates. The legacy helper keeps its UI run loop responsive while waiting
  for commands and exits after ten seconds without a complete command. No
  macOS login credential or authentication mechanism is modified. Actual
  physical sleep, native recovery interaction, new-user login, cross-account
  wake and production root installation remain unverified.
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
- `HotTurkeyBrowserHost` accepts Native Messaging frames only after matching
  its live same-UID parent against protected browser code requirements and a
  configured extension origin. Chromium and Firefox invocation shapes are
  handled separately. Its socket/expected root UID and configuration path are
  fixed in production. It forwards only a browser-role envelope, with native
  parent start identity, a random channel and increasing sequence.
- `TrustedBrowsers` checks that parent against fresh kernel inventory and
  dispatches only extension check/sync, break, tab-grant and append-only popup
  operations. Browser/account/parent generations namespace grants. The native
  session agent supplies foreground/idle context; no elapsed time or caller
  idle value can manufacture website usage. Five-second extension syncs are
  counted with server monotonic time, while long gaps are skipped. Strict
  background targets do not simultaneously earn focus rewards.
- Attested extension heartbeats feed the kernel executor's configured grace
  period. Missing extensions, known unsupported browsers and optional settings,
  installer/Activity Monitor strictness apply only to accounts affected by a
  locked rule. Tests use disposable processes; user applications are untouched.
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
- Protected management also covers settings, inert duplication, atomic imports,
  lock-free configuration exports, categories/users and statistics. Only the
  controller can mutate policy or clear statistics. Other accounts' statistics
  are forcibly scoped to their own account, and their exports cannot bypass
  protected overview. Password changes invalidate old manager tokens.
- `SystemClient` and the CLI's explicit `--system` mode use the fixed root-owned
  native client, never a root database or caller-selected socket. Existing CLI
  commands retain the current-user route by default. Explicit system-mode
  desktop/open routing now uses a separate unprivileged HTTP adapter. Login
  preference delivery and a session supervision plan now have isolated tests;
  production deployment still requires the privileged installer.
- `HotTurkey.app/Contents/MacOS/HotTurkey --system` starts only the system UI
  adapter; it does not invoke the current-user installer or executor. The CLI
  equivalents are `python3 -m hotturkey --system serve` and, in another terminal,
  `python3 -m hotturkey --system open`. Connection files live under the selected
  data directory's `system-desktop/`, separately from the current-user backend.
  The adapter has no policy database. Each HTTP request carries its own settings
  session to the fixed protected client; authentication in one page never
  authenticates other pages. Four concurrent native requests are allowed.
- The shared loopback token, origin/Host validation, strict JSON parser and CSP
  also protect system UI requests. Management and statistics permissions remain
  in the authority. Browser/session/native usage and direct document RPC are
  not exposed by the UI adapter. Other accounts see read-only applicable rules,
  schedules and their own statistics. The native shell accepts commands and
  dialogs only from its current exact HTTP loopback origin.
- UI health distinguishes the local adapter from a fresh kernel executor and
  live session agent. A missing authority produces a connection error with a
  retry action; it never opens a local database or starts alternate enforcement.
  Actual root installation, native system-window interaction and cross-account
  sessions remain unverified. A disposable current-GUI launchd crash/restart
  test verifies passive signed-agent supervision, not an installed root service.
- The trusted session reply can carry an opaque desktop-login ticket, never a
  command or path. Its optional receipt is bound to the verified UID/PID/audit
  token and a genuine audit-login/boot marker. Only first-observed new console
  logins with `open_at_login` enabled request a UI launch. Wake, same-session
  agent/authority restarts and enabling the preference mid-session do not
  manufacture new launches. Disabling the preference cancels pending delivery.
- Launch completion is persisted. Failed or unacknowledged delivery is bounded
  to three attempts per login, with normal failure backoff of 10/30/120 seconds
  and a 15-second acknowledgement window. Tokens and live-process leases are
  ephemeral. A crash after spawn but before the receipt is committed can cause
  another attempt; the native launcher first checks for an already-running
  system app. This is not an exactly-once process-spawn guarantee. A successful
  receipt means the process was spawned or already running, not that WebKit
  finished loading. Enforcement remains independent of UI readiness.
- The launcher fixes `/Library/PrivilegedHelperTools/local.hotturkey/HotTurkey.app`
  and `--system --login`, verifies root ownership, non-writable ancestors and
  executable/metadata, rejects links, and validates the sealed app signature.
  The installed app must have `HotTurkeySystemMode: true` in its signed plist;
  it defaults to protected mode and reads `start_in_tray` from the authority.
  The current-user app retains its existing default. No production path, UID,
  program argument or sample override was added to the native session agent.
- `session_launch.py` renders the future `/Library/LaunchAgents/` plan with a
  fixed native agent, Aqua sessions, RunAtLoad, KeepAlive and a ten-second
  launchd throttle. It does not write or load it. It does not create a new audit
  session on agent restart; its UI child is independent of the sampler's group.
  The transactional installer must deploy the signed app and agent together,
  preserve protected permissions, register the plan and pin the new agent's
  code requirement. Root startup now also requires the protected app paths.
- Large reads use immutable document snapshots. Uploads execute only after full
  length/hash/JSON validation, then pass the normal operation permission/lock
  checks. Transfer ownership includes kernel UID, role, PID and audit token;
  another process cannot take over a cursor. Every page/chunk rechecks current
  password/overview access. Browser pages stay below Native Messaging's one-MiB
  output limit and the extension installs only a fully verified JSON result.
  The extension advertises `document_protocol: 1`; the native host strips that
  capability field before protected policy dispatch. Older decoders receive a
  clear reload response for paged results, and unused cursors are canceled.
- Transfer bounds are 64 MiB per UTF-8 document, 128 MiB reserved total, four
  records per UID, 256 KiB binary chunks and an absolute 120-second lifetime.
  These are byte-buffer bounds, not a bound on all parsed-policy heap or CPU.
  Interrupted uploads do not modify policy. Completed mutations are not
  automatically retried if delivery of their result fails. Large operations
  and hostile-load recovery still need production installation validation.
- The ordinary current-user Python host also pages large responses, using a
  process-local cache without kernel peer attestation. Its existing extension
  operation allowlist is unchanged. This compatibility path does not gain the
  protected service's code/parent verification or anti-tamper guarantees.
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
  rejected/stale actions are not reported as successful blocks. Management RPC
  exposes no process-list, PID-kill or caller-supplied usage operation.
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

The local ad-hoc build pins distinct client, session-agent and browser-host
`cdhash` values. Protected `authority.json` now requires version 3,
`controller_uid`, and `requirements` with exactly `client`, `session` and
`browser` pinned requirement strings.
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
python3 tests/integration_trusted_browsers.py
python3 tests/integration_management.py
python3 tests/integration_legacy_documents.py
python3 tests/integration_system_desktop.py
python3 tests/integration_session_desktop.py
python3 tests/integration_session_supervision.py
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

Browser integration uses an explicitly signed test parent and the QA browser
host, both excluded from the app bundle. It verifies real parent code, origin,
kernel PID/start identity, role separation, locked additions, single-tab grants,
Chromium/Firefox argument formats and wrong-server rejection. Its test parent
is not a real browser; evidence in `build/trusted-browser-proof.json` explicitly
records that distinction. Native Messaging framing and invocation formats
follow [Chrome's documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
and [Mozilla's documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

The production host reads root-owned `browsers.json` beside the executables:
version 1 with a `browsers` object keyed by the supported browser names. Each
entry has a Security-framework `requirement` and an explicit `origins` array.
Chromium origins are extension URLs; Firefox uses the add-on ID. The future
installer must select actual approved vendor signatures, maintain root-owned
host manifests and deploy an extension whose code the account cannot modify.
An editable unpacked extension or developer tools can undermine browser
reports even when the native parent is authentic. That deployment/tamper
boundary is unresolved; this foundation is not enabled by the current app.

`integration_management.py` sends over one MiB of Unicode targets through the
real signed client and actual bounded socket frames. It verifies upload and
read-back integrity, unchanged locks during large additions, imports/exports,
duplication, password/overview checks, paged statistics, charges surviving
statistics deletion, and an abandoned upload whose new process cannot resume
it. A reachable QA server returning a corrupt document is rejected by the
native client before any partial result reaches stdout. This is ordinary-user
isolated transport evidence, not an installed root-service test.

The browser fixture additionally sends an over-one-MiB report through the
signed host and resolves 4,000 Unicode targets using the extension's actual
JavaScript decoder. It verifies that every host-to-browser frame remains below
one MiB. The signed test parent is still not a real browser.

## Work still required before system installation

1. Deploy the login/tray delivery and session supervision plan through the
   privileged installer, then validate the installed native system window and
   actual login/tray behavior. Explicit desktop/CLI routing, protected
   management and browser paging now have isolated tests; default desktop
   launches continue to use the existing current-user service until a system
   installation explicitly selects protected mode.
2. Install/supervise the trusted session agents and complete browser heartbeats,
   notifications and authorized device actions. Protected browser transport,
   heartbeat accounting and executor strictness now have isolated tests, but
   production browser deployment and tamper resistance remain unverified.
   Foreground/idle and native
   login/wake observations now have an isolated trusted path, but real GUI
   allowance expiry, sleep/wake and cross-account session transitions remain
   unverified. Missing agents do not invent activity; supervision and tamper
   recovery must be validated before this becomes a protective system mode.
   Browser strictness still needs real-browser and cross-account validation.
3. Provide a reviewed, transactional privileged installer, migration, startup,
   update and lock-aware uninstall path. Current expected paths are
   `/Library/PrivilegedHelperTools/local.hotturkey`,
   `/private/var/db/local.hotturkey` and
   `/private/var/run/local.hotturkey/control.sock`; no files are placed there by
   the current installer.
   The preparation tool, sealed payload verification, private SQLite migration
   and durable filesystem transaction components now exist and have isolated
   tests; see [the preparation workflow](SYSTEM-INSTALL.md). They do not yet
   coordinate service cutover, activate an installation or provide a complete
   production uninstall path.
4. Validate actual separate macOS accounts, login/logout, sleep/wake, crashes,
   tampering, upgrades and recovery, including ordinary-user bypass attempts.
5. Complete distribution signing/notarization. Root/admin recovery remains an
   explicit boundary; no user-space tool can promise protection against an
   administrator who controls the machine.
