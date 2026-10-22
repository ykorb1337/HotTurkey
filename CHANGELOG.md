# Changelog

## 0.2.0 — 2026-10-22

- Temporarily unblock one tab for one rule, directly when unlocked or after text/password verification. Other tabs, applications and overlapping rules remain enforced; grants expire and are not persisted to disk.
- Import website or exception lists from multiple other rules, with preview and deduplication. Locked destinations accept blocked-site additions while preserving the lock, timers and allowance charges.
- Keep the desktop reconnecting when a background service starts slowly, backing off after the initial attempts. Desktop logs are bounded.
- Verified the real installed Edge extension: text/password/direct grants, independent tabs/rules, automatic expiry, reopening tabs and internal-page closure. Isolated native UI tests cover imports, cancellation and a deliberately delayed backend.

The release remains a preview. Safari, system-level tamper resistance, full multi-account enforcement and distribution signing/notarization are still open.

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
