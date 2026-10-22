# Changelog

## 0.1.0 — 2026-10-22

First public preview of HotTurkey, an independent macOS focus blocker inspired
by Cold Turkey Blocker.

- Native desktop application, current-user background service, browser extension
  and command-line interface; all data stays on the Mac.
- Website and application blocking, per-rule exceptions, weekly schedules,
  several locks, allowances, text breaks and pomodoro timers.
- Add blocked websites or applications to a locked rule without removing its
  existing targets or resetting its lock and timers.
- Fixed rule deletion in the native window and application enforcement,
  including Steam launchers; added executor and desktop connection recovery.
- Bundled, checksummed Python runtime, transactional current-user installer and
  Apple Silicon ZIP package.
- Experimental signed-client policy RPC with kernel identity verification and
  shared-account policy tests; it is not installed or connected to enforcement.

This preview does not yet provide complete Cold Turkey feature parity. Safari,
system-level tamper resistance, full multi-account enforcement, distribution
signing/notarization and several browser features remain open. Intel and older
macOS versions have not been tested. See [docs/PARITY.md](docs/PARITY.md) and
[docs/VALIDATION.md](docs/VALIDATION.md).
