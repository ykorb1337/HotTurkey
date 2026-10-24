# HotTurkey for macOS

<img src="assets/icon.svg" width="96" height="96" alt="HotTurkey icon">

**Cold focus. Open source.**

An independent, open-source macOS focus blocker inspired by **Cold Turkey
Blocker**. Block distracting websites and apps, schedule focused time, and keep
your rules locked while still adding new distractions to the list. Native
desktop app, browser extension, background service and CLI. Local data. MIT
license.

[Download the Apple Silicon preview](https://github.com/ykorb1337/HotTurkey/releases)
· [Feature coverage](docs/PARITY.md) · [Contributing](CONTRIBUTING.md)
· [Security](SECURITY.md)

**Preview, not full feature parity.** Edge has been tested on this development
Mac; other browsers need verification. Safari, system-level tamper resistance,
complete multi-account enforcement, Developer ID signing and notarization are
not yet available. The download is an ad-hoc signed Apple Silicon build; Intel,
older macOS and other machines have not been tested. The protected policy
service is experimental and is not enabled by the installer.

HotTurkey 是受 Cold Turkey Blocker 公开功能启发、独立实现的开源 macOS 专注工具。当前已有可运行的应用、后台、扩展与命令行，**尚未完整覆盖原版功能**。完整对照见 [功能覆盖表](docs/PARITY.md)，验证记录见 [验证报告](docs/VALIDATION.md)。与 Cold Turkey Software 无关联；未使用其源代码、素材或授权系统。

## 打开应用

本机应用会安装到 `~/Applications/HotTurkey.app`；构建副本位于 `build/HotTurkey.app`。双击打开即可连接已安装的后台。`build/HotTurkey QA.app` 使用项目内 `.runtime` 测试数据，与正式数据独立。

从源码构建需要 macOS、Python 3.9+ 和 Apple Command Line Tools：

```sh
python3 scripts/build.py
```

首次构建会从 Astral 官方发布下载已固定 SHA-256 的 Python 运行时及许可证档案，后续使用本地缓存。`--archive` 可生成保留签名和链接的 ZIP 包。仅供开发的 `--system-python` 选项会保留对构建机 Python 的依赖，请勿用于分发。

登录打开界面和只显示菜单栏图标可以在设置中独立选择；默认关闭，不影响后台守护。

默认构建包含固定版本的独立 Python，应用、登录后台和浏览器桥接均使用它，无需运行机器另装 Python 或开发工具。当前已验证 Apple Silicon 构建；仍未使用 Developer ID 签名及公证，也未完成旧 macOS、Intel 和独立机器安装验证。

## 当前能力

- 网站规则：域名及子域名、URL 路径、通配符、搜索关键词、YouTube 频道、整个互联网、每规则独立例外、文本导入导出与内置分类。
- 浏览器内部页：可添加 `edge://settings`、`chrome://extensions` 或 `about:addons`，命中时关闭标签页；宽泛通配符保留新标签页和扩展管理等页面，需显式指定才会拦截。Edge 已实测带唯一标记的内部页关闭与拦截记录。
- 应用规则：Bundle ID、应用路径、文件夹、可执行文件；后台检查并结束命中的用户进程。Steam 客户端和游戏快捷方式会解析到实际安装目录，包含额外游戏库。
- 跨规则导入：在网站或网站例外编辑器中选择其他规则，可多选屏蔽网站或例外列表，预览去重后合并，保存目标规则后才生效。锁定目标只能追加屏蔽网站，来源规则不变。
- 每周日程：跨午夜、多天重复、拖动创建时段、每时段独立休息设置、显示其他规则。
- 锁定：定时（只能延长）、时段、随机字符/单词/自定义文本、密码、等待、日程及重启锁。
- 锁定期间可继续向同一条规则新增屏蔽网站和应用；界面提供只追加的编辑入口，保留锁定、日程与休息计时。文本锁也可增加验证长度，保留原文并追加内容；删除或替换已有项目、修改例外及其他配置仍需先解锁。
- 单标签页临时放行：拦截页可对未锁定规则直接申请，或通过该规则的文本/密码验证，选择 1–1440 分钟。只跳过当前标签页中所选规则的网站拦截，其他规则、其他标签页及应用仍受限；关闭标签页、后台重启、规则变更或到期后失效。
- 休息：番茄钟（持续规则可重置为新的完整专注阶段）、日/周/月/日程/滚动使用额度、专注奖励、文本/等待后休息、会话次数。
- 自动启动：指定时间、每天、登录/唤醒、下一个日程时段。
- 统计：本地 SQLite、网站/应用时长、拦截次数、日期/用户/规则/类别/关键词过滤、JSON 导出及删除。删除统计不会重置额度。
- 偏好：浅色/深色/系统主题、周起始日、24 小时制、闲置计时、隐私窗口统计偏好、设置密码。
- 设备规则：锁屏、注销、关机的执行接口；持续设备规则使用有限时长并自动定时锁定，到期停止；这些动作仍需单独的真实设备测试及权限验证。
- 防绕过选项：锁定时阻止活动监视器、系统设置、安装器、已知不受支持浏览器，或扩展离线时关闭支持的浏览器。默认均关闭。

## 安装后台和扩展

本项目没有账号、云服务或遥测。扩展读取网址、频道信息、前后台状态与闲置状态，通过 Native Messaging 与本地后台通信。无需让网页访问本地 API。

1. 在 Edge / Chrome / Brave 等浏览器的扩展管理中开启开发者模式，加载 `extension` 文件夹。
2. 复制生成的扩展 ID。
3. 在桌面应用的“浏览器与安装说明”中填入扩展 ID，点击“安装 / 更新当前用户后台”。首次也可先留空安装，再从界面给出的稳定扩展文件夹加载扩展、填入 ID 并更新。整个流程使用应用内运行时。

开发时仍可运行安装命令：

```sh
python3 scripts/install.py --extension-id 你的32位扩展ID
```

安装到 `~/Library/Application Support/HotTurkey/runtime`，登录启动清单为 `~/Library/LaunchAgents/local.hotturkey.service.plist`。后台通过 launchd 自动重新启动；关闭或退出界面不会关闭后台。安装器不会自动创建拦截规则。新程序先暂存，停止旧后台后再替换；启动失败时恢复旧程序和连接配置，不替换数据库。已有浏览器扩展 ID 会保留。

原生执行器异常退出或无响应时，后台会自动重启它，并在界面显示“正在恢复拦截”。重试间隔逐步增加至最多 30 秒；等待恢复期间继续处理日程与锁定计时。执行器重启不会被当成新的登录事件。

桌面页面发生导航失败或 Web 内容进程退出时会自动重新连接，最多重试 3 次。连接后台时则持续自动重试，等待较久后降低频率，不因冷启动超过 9 秒而放弃；日志大小有界，不记录页面 URL 或连接令牌。

`--extension-id` 可重复指定。浏览器加载路径变化可能改变扩展 ID，必须重新注册。推荐先执行 `--prepare-only`，再加载安装目录下的 `runtime/extension`，最后带 ID 执行安装命令。

Firefox 构建在 `build/firefox-extension`；普通发行版需要 Mozilla 签名才能永久安装。Safari 扩展尚未实现。

如果需要在隐私窗口中使用，须手动允许扩展在隐私窗口运行。本地文件拦截同样需要文件 URL 权限。

## 开发预览

```sh
python3 -m hotturkey serve --data .runtime
python3 -m hotturkey --data .runtime open
```

预览服务不会执行应用或设备动作。加入 `--enforce` 才启动原生执行器。所有服务入口均使用单实例文件锁，避免多个后台覆盖同一数据目录。

## 命令行

在项目目录运行：

```sh
python3 -m hotturkey status
python3 -m hotturkey create "深度工作" --web reddit.com --web youtube.com
python3 -m hotturkey add "深度工作" youtube.com/@learn --to exceptions
python3 -m hotturkey start "深度工作"
python3 -m hotturkey lock "深度工作" --minutes 60
python3 -m hotturkey check https://reddit.com
python3 -m hotturkey export blocks.json
python3 -m hotturkey stats --export statistics.json
```

命令行与界面共享相同的锁定和设置密码检查。设置密码开启时，会交互要求验证。设备规则启用需显式 `--confirm-device`。持续番茄钟可用 `python3 -m hotturkey reset-pomodoro "规则名"` 重置；文本锁可再次使用 `lock "规则名" --text-length 新长度` 增强。

导入默认停用新规则并关闭自动启动。需要保留计划时使用 `import blocks.json --keep-autostart`；保留设备自动启动还需加 `--confirm-device`。实验性的 `--system` 通过受保护原生客户端管理共享规则，需要后续特权安装才能在正式环境使用；它不读取或替换当前用户数据库。可用 `python3 -m hotturkey --system serve` 启动独立桌面入口，再用 `python3 -m hotturkey --system open` 打开；原生应用的可执行文件也接受 `--system`。默认启动方式继续使用当前用户后台。

## 数据与恢复

- 正式数据：`~/Library/Application Support/HotTurkey/hotturkey.sqlite3`。
- 测试数据：项目内 `.runtime`。
- 日志：数据目录中的 `service.log`、`launch.log` 和 `launch-error.log`。不会记录授权令牌或密码。
- API 仅绑定 `127.0.0.1` 动态端口，使用每次启动重新生成的令牌、Host 检查和 Origin 检查。连接文件和数据库只允许当前用户读取。
- 密码保存为带随机盐、200000 次 PBKDF2-SHA256 的摘要。
- 计时在当前进程内结合墙钟与单调时钟，降低向后调整时钟的影响；这不是系统级时间防篡改。

支持的卸载路径：

```sh
python3 scripts/install.py --uninstall
```

锁定中的规则会阻止此卸载命令。卸载保留数据库，浏览器扩展可在浏览器管理页移除。当前后台是用户级服务，同一用户仍可直接修改文件或停用 launchd；**还没有原版级别的防删除、防篡改与跨用户强制能力**。

## 验证

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node tests/extension.test.cjs
node tests/browser_pages.test.cjs
node tests/tab_exceptions.test.cjs
```

`tests/integration_macos.py` 只拦截它自行编译的临时测试进程。`tests/edge_fixture.py` 是真实 Edge 验证用的临时规则工具，需按验证报告执行并在结束时清理。

`python3 tests/integration_recovery.py` 使用独立临时后台，验证执行器退出、挂起、自动恢复和关停；只结束它自己的执行器和一次性测试程序，不修改已安装后台或用户规则。

`python3 tests/integration_runtime.py` 会将完整应用搬移到含中文和空格的新路径，在无开发工具 PATH 的环境下实际验证内置解释器、后台、原生拦截和 Native Messaging，并核对动态库依赖与运行后的签名。

共享策略与系统通信基础位于 `authority.py`、`authority_server.py`、`ipc.py` 和原生 `PolicyClient.swift` / `PeerCheck.swift`，当前未接入已安装后台。真实签名客户端已验证按系统身份管理规则、锁定中追加、设置密码保护和重启持久化；普通用户代码即使使用相同 UID 也不能冒充客户端。生产入口要求受保护的 root 安装路径，应用不自动启用该服务。它尚未构成系统级防卸载或多账号强制功能；边界与后续工作见 [系统服务说明](docs/SYSTEM-SERVICE.md)。`python3 tests/integration_peer.py` 和 `python3 tests/integration_authority.py` 可在 `--qa` 构建后运行，不需要安装系统服务。

`python3 tests/integration_startup.py --prepare` 会生成故意延迟后台启动的独立应用。手动打开所返回的测试应用，运行 `--verify` 检查超过旧等待上限后自动恢复；测试不注册登录项或改动正式数据。

## 实现结构

`hotturkey/model.py` 验证配置，`engine.py` 实现策略与计时，`store.py` 保存状态和统计，`server.py` 为桌面与 CLI 提供本地接口。`native/Agent.swift` 负责 macOS 进程和设备动作，`native/Desktop.swift` 提供原生窗口、菜单栏和文件选择。`extension` 通过 Native Messaging 获取策略；普通域名使用浏览器网络规则，复杂路径例外和频道规则由内容脚本与同一策略引擎执行。

参考公开文档：[Cold Turkey 功能页](https://getcoldturkey.com/features/)、[用户指南](https://getcoldturkey.com/support/user-guide/)。本项目与 Cold Turkey Software 无关联，不使用其源代码、品牌素材或商业授权系统。

## 内置运行时与第三方许可

运行时来自 [Astral Python Build Standalone](https://github.com/astral-sh/python-build-standalone)，版本、架构、下载地址和校验值固定在 `runtime/python.lock.json`。构建时同时保留上游构建元数据和其引用的许可证文本，位于应用的 `Contents/Resources/ThirdParty/Python`；运行时自身的其他许可文件也保留在原目录。原生程序明确以 macOS 12 为最低构建目标，此声明不等同于旧系统实测。

HotTurkey 自有代码按 [MIT License](LICENSE) 开源；第三方组件遵循各自许可。

## New in 0.3.0

The toolbar popup can append the current domain or path to an existing rule, including a locked rule. It respects the settings password, preserves exceptions/timers/toggles, and does not save URL queries or fragments. The real Edge domain flow has been tested; path/password UI flows were tested with explicit browser API doubles and real Native Messaging.

Interface size is adjustable from 50–200% in Settings, with Command/Ctrl plus/minus or scrolling, and star/zero reset. The size is saved locally. Dialogs and navigation adapt to the effective viewport, and calendar dragging uses scaled coordinates. Native keyboard and 150% calendar interactions have been tested; native mouse gestures remain unverified.

The unreleased protected-service foundation connects management RPC, a kernel process executor, a separately attested native session agent and a restricted browser host. Settings/import/export/statistics and explicit `--system` CLI/desktop routing now have isolated tests, including large Unicode document transfers. The system desktop adapter carries per-page password sessions and never falls back to a current-user database. Parent browser code/origin and fresh kernel identity are checked before browser operations; missing session activity earns no credit. It is not enabled by the current-user installer. Production session deployment and actual login/window validation, browser deployment/tamper validation, privileged installation/migration and real separate-account/sleep-wake validation remain required; see [the system-service boundary](docs/SYSTEM-SERVICE.md).

The original turkey icon uses warm tail feathers, a cream body and a dark tile.
Its editable vector source is `assets/icon.json`; `scripts/build_icons.py`
generates SVG, extension PNGs and the macOS ICNS without external graphics
dependencies. The normal macOS build includes it automatically.

Import now previews rule names and defaults new rules to inactive with automatic
starts off. Retaining automatic plans is an explicit choice; device plans also
need confirmation. CLI import supports `--keep-autostart` and, for retained
device plans, `--confirm-device`. Existing rules and their locks are preserved.

The protected session agent now delivers login-UI requests using kernel audit
login markers, bounded retries and persisted acknowledgements. It launches only
the fixed root-owned signed system app; duplicate tickets and same-session
restarts do not repeatedly spawn the UI. A disposable launchd test verifies
crash recovery of the signed passive agent. Production system installation and
actual native login/tray behavior are still pending.
