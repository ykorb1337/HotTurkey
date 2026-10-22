# Protected policy service: current boundary

Status: experimental foundation, **not installed** by the application or
`scripts/install.py`. The released application still runs only the current
user's service. This work does not yet provide system-level blocking,
anti-uninstall protection or cross-account enforcement.

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

## Work still required before system installation

1. Connect policy RPC to desktop, browser bridge and command-line clients with
   complete settings/import/export/statistics support and large-policy paging.
2. Implement protected process enumeration and enforcement independently of
   user-reported samples, plus trusted per-session agents for foreground/idle
   information and authorized device actions.
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
