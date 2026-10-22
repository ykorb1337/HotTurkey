# Security

HotTurkey currently runs a **per-user** background service. The same macOS user
can stop it or edit its files. It is not yet a tamper-resistant system service.
The protected policy RPC work is an uninstalled foundation, not a security
boundary used by the released application. See [docs/SYSTEM-SERVICE.md](docs/SYSTEM-SERVICE.md).

The desktop API binds only to loopback and checks its per-start token, Host
and Origin. Native Messaging accepts a narrow set of browser operations.
Passwords use salted PBKDF2-SHA256; browsing statistics remain local. These
controls do not protect against a compromised account with access to the local
database and connection file.

Please report vulnerabilities through the repository's private vulnerability
reporting feature when available. If it is unavailable, open an issue asking
for a private reporting channel without including exploit details, tokens,
passwords or personal browsing data. No response-time guarantee is offered.
