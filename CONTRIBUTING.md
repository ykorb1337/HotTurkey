# Contributing

HotTurkey is an independent, open-source macOS focus blocker inspired by Cold
Turkey's public feature set. The feature coverage table in
[docs/PARITY.md](docs/PARITY.md) records both implemented behavior and open gaps.

For a change, describe the user-visible behavior, keep it scoped, and include
the checks that demonstrate it. Preserve the lock invariant: adding blocked
targets is allowed while locked; removing targets, changing exceptions or
weakening a rule requires unlocking it.

Run the local suite on macOS:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node tests/extension.test.cjs
node tests/browser_pages.test.cjs
node tests/tab_exceptions.test.cjs
node tests/quick_add.test.cjs
node tests/text_size.test.cjs
node tests/document_transfers.test.cjs
node tests/import_preview.test.cjs
python3 scripts/build.py --qa
python3 tests/integration_peer.py
python3 tests/integration_authority.py
python3 tests/integration_system_enforcement.py
python3 tests/integration_trusted_sessions.py
python3 tests/integration_trusted_browsers.py
python3 tests/integration_management.py
python3 tests/integration_legacy_documents.py
python3 tests/integration_runtime.py
```

The integration tests above use disposable data and processes. Build with the
bundled runtime for the relocation test. `integration_applications.py` and
`integration_recovery.py` also use isolated services. `integration_macos.py`
and `edge_fixture.py` target a running application and must be run deliberately
against an appropriate test installation; they are not part of automated CI.

Do not include databases, connection files, logs, credentials, signing identities
or browsing histories in commits or issues. Screenshots and diagnostics should
use synthetic rules. Code contributions are accepted under the MIT license;
bundled third-party components retain their own licenses.

The signed browser integration also uses Node.js to run the extension's actual
document decoder against the test parent/host. If Node is not on PATH, set
`HOTTURKEY_TEST_NODE` to its executable for that test.

For interactive block-page QA, `python3 tests/integration_tab_ui.py` starts a
local isolated fixture using the actual worker, backend and Native Messaging
with browser API doubles. It is not a substitute for installed-extension tests.

`python3 tests/integration_popup_ui.py` starts the disposable popup and manager UI fixture. Browser APIs are explicit doubles; the backend and Native Messaging are real. It does not modify installed data or browser registration.
