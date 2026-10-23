# 验证记录

环境：2026-10-22，macOS 27.2，Apple Silicon，Swift 6.4（以 Swift 5 兼容模式构建），Python 3.9.6。界面通过 Codex in-app browser 与真实 WKWebView 桌面应用验证；网站扩展在真实 Microsoft Edge 中安装并验证。

## 自动验证

- Python rules/services: 214 passed with bundled Python 3.13; earlier system Python 3.9 run passed 213. 覆盖域名边界、路径和通配符、频道例外、规则独立性、跨午夜、锁定与到期、重启身份、时钟回退、各休息类型、并发额度去重、导入原子性、设置密码、Origin/Host 检查、Native Messaging 帧和操作权限隔离；执行器分片 UTF-8、半行超时、无效输出、超大帧、管道堵塞、停滞期间策略计时、关停及忽略终止信号的子进程清理验证。
- 其中 18 项验证未启用的共享策略层：按 UID 隔离额度、会话、奖励、文本休息和统计；共享锁、日程启动与设备到期；旧数据迁移不重置额度；管理账号与设置密码限制。使用独立临时数据库，不代表已完成真实跨账号执行。
- 其中 10 项验证本机 IPC 帧与边界：分片、截断、非法长度与 JSON、总超时，以及内核提供的真实 UID/PID；未注册系统监听服务。
- JavaScript 扩展策略与网络规则检查：67 项通过；浏览器内部页执行与竞态检查：12 项通过；单标签页授权、隔离、到期与网络规则检查：17 项通过。覆盖规则匹配、独立例外、复杂例外降级及按标签页生成 session rules。
- JavaScript 语法检查：管理界面和扩展脚本通过。
- 登录界面配置通过临时目录测试，不在测试中修改真实登录项。
- 原生应用与执行器编译成功，ad-hoc 签名成功。

## 真实执行验证

- 原生进程拦截：测试自行编译并启动一个只休眠的可执行文件，临时规则只匹配该文件；后台将其以 SIGTERM 结束，原生 helper 心跳保持在线。随后删除临时规则。
- 桌面：`HotTurkey QA.app` 打开成功，WKWebView 显示在线后台、规则状态与番茄计时。
- 界面：创建规则，输入 3 个网站和 2 个例外，设置番茄钟，配置周一至周三 09:00–17:00，保存后列表和日程一致。
- 日程拖动：将周二 09:00–17:00 移至周四 10:00–18:00，周一与周三保留；拖动周五空白区域，新建并保存 07:00–08:00。
- 自定义日期：界面显示并提交起止日期过滤。
- 退出界面：通过 Command-Q 完全退出桌面进程后，已安装后台仍能结束一次性测试程序，helper 心跳在线。
- 后台恢复：实际重启 launchd 服务后，后台进程及端口发生变化，原生界面自动从旧端口切换至新端口并重新显示在线状态，无需用户重开应用。
- 执行器恢复：`tests/integration_recovery.py` 在独立临时数据中运行真实后台和执行器。强制结束执行器后约 1.20 秒恢复；暂停执行器后约 12.21 秒恢复。每次恢复后，一次性测试程序均再次被 SIGTERM 结束；定时锁和规则保留，未把执行器重启当成登录事件，执行器暂停期间仍按时启动一次性规则。关停耗时约 0.76 秒，无遗留子进程。证据：`build/recovery-proof.json`。时间为本次测量，并非所有环境的保证。
- 恢复状态界面：在独立 QA 版临时模拟执行器不可执行，真实 WKWebView 显示“正在恢复拦截”；恢复测试文件权限后自动回到“本地后台正在守护”，QA 规则保持一致。截图：`build/Recovery-in-progress.png`、`build/Recovery-restored.png`。
- 进程身份原型：`tests/integration_peer.py` 使用临时 Unix socket 和一次性签名进程，验证真实 UID/PID、允许的代码签名哈希、错误哈希拒绝及进程退出后审计令牌失效。证据：`build/peer-identity-proof.json`。这是普通用户环境中的通信核验，未安装或测试 root 后台。
- 删除确认：修复 WKWebView 未接通 JavaScript 确认框导致删除被静默取消的问题。真实 QA 桌面中，取消后临时规则仍在，确认后仅该规则消失；原有 QA 规则保留。输入框和提示框也接入原生弹窗。
- 等待锁：设置 1 分钟等待锁；开关与删除禁用；启动等待，等待结束后通过验证解锁，随后停用测试规则。
- Edge：开发者模式安装扩展；Native Messaging 在线，当前用户 launchd 后台在线。
- Edge 网站拦截：临时规则拦截 `example.com`，实际显示 HotTurkey 拦截页及命中的规则名称。
- Edge 路径例外：同一规则下 `example.com/learn` 实际可以访问。
- Edge 一分钟额度：有额度时实际打开网站，额度耗尽后自动切换为 HotTurkey 拦截页。
- Edge 文本休息：拦截页显示挑战文本，手动输入 `focus` 并验证后实际恢复访问网站。
- Edge 网络层：无路径例外时使用 session DNR 规则，拦截后的 URL 以 `blocked.html#url=https://example.com/?hotturkey=network` 保留原网址，显示正确规则名。
- Edge 测试完成后删除临时规则并恢复后台标签页与严格计时设置；保留用户授权安装的后台与扩展。

截图：`build/HotTurkey-preview.png`、`build/Edge-blocked.png`。

## 应用拦截修复验证

`tests/integration_applications.py` 在独立临时数据中验证 AppKit 应用、没有 GUI 登记的后台 .app、无 .app 后缀的 Steam 客户端替身及游戏快捷方式替身。四种目标均被实际结束，无关测试进程保留；后台替身主动忽略 SIGTERM，仍被强制结束。证据：`build/application-block-proof.json`。

修复内容包括：原生进程补全应用身份、终止失败后的强制结束、Steam XML plist 的尾部 NUL 兼容、从游戏库清单解析快捷方式的实际目标，以及 Steam 私有客户端路径匹配。未执行任何快捷方式脚本来做解析。

安装后实际启动本机 `/Applications/Steam.app`：后台产生新的 Steam 应用拦截事件，随后进程列表中已无 Steam 本体或私有客户端进程。三条既有规则与设置摘要保持一致。证据：`build/installed-applications-proof.json`。

## 锁定期间新增屏蔽项目

新增独立的、需管理权限的追加操作。网站和应用列表在同一把锁内校验后合并，不接受例外、开关、锁定或其他设置的修改；重复提交去重，多个编辑窗口的追加不会相互覆盖。命令行新增网站与应用使用同一操作。

自动测试覆盖七种锁、密码锁哈希持久化、旧项目保留、无效输入原子拒绝及总列表长度上限；验证额度、会话、奖励、休息挑战、设备结束时间和暂停状态不重置。设置密码和浏览器 Native Messaging 权限隔离仍有效。

真实 `HotTurkey QA.app` 中打开文本锁规则：原项目只读，新增网站后切到应用页，手工输入一个应用并通过原生选择器再加入一个测试应用，切回网站页确认输入保留，再保存。保存后仍为文本锁，原有网站和应用保留，新网站命中拦截，应用列表同时包含手工与原生选择结果。证据：`build/locked-additions-ui-proof.json`、`build/Locked-additions-editor.png`。生产规则未用于测试。

`tests/integration_applications.py` 更新为先锁定规则，再追加网站与应用。四类真实一次性进程均在追加后被结束，新增网站立即命中，锁定信息保持一致，无关进程保留。证据：`build/application-block-proof.json`。

## 浏览器内部页面拦截

按 [官方内部页面说明](https://getcoldturkey.com/support/how-to/block-chrome-urls/) 实现 chrome://、edge:// 和 about: 规则；普通全网站通配符不影响内部页，内部页通配符保留新标签页、扩展管理、欢迎页，显式列出仍可拦截。Chrome 规则也识别 Brave、Vivaldi、Opera 的对应内部协议。

Python 与扩展使用同一组 39 个预期样例核对匹配、例外与受保护页面。扩展通过标签页事件和定期复核执行关闭；返回较慢时重新确认 URL，避免误关已经导航到允许页面的标签页。测试覆盖并发去重、关闭失败、前后台设置、隐私状态、离线缓存、既有标签页复查。原生后台在成功关闭报告后再次核验策略，再记录拦截和投递通知；通知开关和隐私统计偏好仍有效。

此前的真实 Edge 自动化曾因窗口状态和 AX 超时中断。此次在新建测试窗口中成功重新加载已有扩展，向临时锁定规则追加唯一的 `edge://version/#hotturkey-internal-qa` 目标；实际打开后该测试标签页自动关闭，回到原测试标签页，后台记录 1 次对应的拦截。普通版本信息页不匹配这个唯一标记，用户其他内部页不受该测试规则影响。测试结束移除临时规则并核对原策略摘要一致。证据：`build/edge-tab-proof.json`。Chrome 与 Firefox 内部页尚未实测。

## 番茄钟重置、文本锁增强及界面导航恢复

持续番茄钟重置只更新番茄钟的专注起点，保留规则开启时间、锁、设备结束时间和其他额度账目。支持当前专注或休息阶段重置；日程规则、暂停规则及其他休息类型被拒绝。午夜继续使用午夜作为起点。测试覆盖重启后的计时保留、设备结束不延长、继承休息的清除及未启用共享策略层中的多账号同步。

文本锁增加长度时只在已有文本后追加，不能缩短、替换文本或更换锁类型；文本模式保留，兼容旧锁、Unicode 和自定义换行文本，长度上限 5000 字符。新文本持久化后，原答案无法解锁。两项操作均受设置密码和管理账户限制。

真实 `HotTurkey QA.app`：将文本锁从 10 字符增加至 20 字符，界面和数据库均保留旧文本前缀及锁定状态；等待一分钟进入真实番茄休息阶段，取消重置后仍在休息，确认重置后立即回到 60 秒专注阶段，文本锁保持一致。临时规则已清理，其他 QA 规则保留。证据：`build/timer-ui-proof.json`、`build/Text-lock-extension.png`、`build/Pomodoro-reset.png`。

原生壳加入连接/加载提示、导航失败和 Web 内容进程退出后的有限重试。独立 `HotTurkey Navigation QA.app` 的一次性服务将首次请求重定向到失效本机端口；原生日志记录 `NSURLErrorDomain -1004`，约 0.5 秒后重新加载，界面实际显示恢复成功。证据：`build/navigation-recovery-proof.json`、`build/Navigation-recovery.png`。此前测试中冷启动后台窗口的空白画面在置前后即可显示，日志表明页面本已加载；不将该现象算作网络加载失败。

## 内置运行时、可迁移性及安装事务

运行时固定为 Astral Python Build Standalone 20261021 发布中的 CPython 3.13.17。安装归档及对应完整构建归档均按官方发布 SHA-256 校验；保留构建元数据引用的 14 份许可证文本和运行时原有许可文件。解包前检查路径、链接、文件类型和大小，拒绝越界与目录链接。运行时原生文件逐一 ad-hoc 签名，再签署完整应用。

`tests/integration_runtime.py` 将完整应用复制到含中文和空格的新路径，将 PATH、PYTHONHOME、PYTHONPATH 指向无效位置，再用显式内置解释器启动。标准库模块、后台 API、真实原生执行器和 Native Messaging 均通过；锁定后新增的独立测试程序被结束，锁定信息保留。审计 10 个运行时 Mach-O 组件，未发现应用外的开发工具依赖；整体签名在搬移和运行后均有效。证据：`build/portable-runtime-proof.json`。这不等同于已在另一台 Mac 上验证。

新安装器暂存代码和应用后才停止旧后台，启动失败会恢复程序、登录项及浏览器清单；不替换策略数据库，保留已有扩展 ID。单元测试覆盖注册信息、策略与额度保留、锁定拒绝、同一应用源不被移除、失败恢复，只重连当前用户旧目录中的 Native Messaging 主机，以及并发安装/卸载互斥。

桌面通过相对应用资源路径启动内置 Python，并使用异步本地连接探测。真实 QA 冷启动中记录到旧端口连接失败，随后自动连接到新内置后台；进程路径确认不是 Command Line Tools。测试版点击安装被明确拒绝，不会写入正式安装。原生程序现显式指定 macOS 12 为最低构建目标；旧系统兼容性仍需实机验证。

正式安装已迁移到应用内 Python，登录项和 Native Messaging 启动脚本均不再引用开发工具解释器。真实桌面中留空扩展 ID 并点击“安装 / 更新当前用户后台”后，后台 PID 和端口更新，窗口自动恢复在线；规则与设置摘要、Edge 扩展注册均保持一致。进程路径确认后台和浏览器桥接均使用内置 Python，签名仍有效。证据：`build/gui-bundled-install-proof.json`、`build/installed-embedded-runtime-proof.json`、`build/Bundled-runtime-install.png`。

## 受身份保护的策略通信

新增 15 项策略 RPC 测试，覆盖管理账号限制、设置密码、会话内存上限、锁定中原子追加、异常输入、单个慢连接、错误身份在读取请求前被拒绝、socket 不误替换及策略时钟失败后退出。JSON 解析还拒绝指数溢出成无穷大、重复键和过大整数。

`tests/integration_authority.py` 使用真实签名原生客户端和临时 Unix socket，验证内核 UID/PID、允许的代码身份、相同 UID 普通 Python 代码被拒绝、伪造 UID 字段被拒绝、锁定中追加、设置密码与概览保护。后台重启后规则、追加项目和定时锁保持，旧管理会话失效。客户端在发送密码前拒绝错误 UID 的服务端；生产客户端不接受 QA 路径和 UID 参数。证据：`build/authority-rpc-proof.json`。QA 客户端未打包，生产客户端路径固定；原生执行器和客户端开启 Hardened Runtime。

这是普通用户隔离环境中的真实通信验证，未安装 root 服务，未替换正式后台，未完成系统执行器、跨账号强制或防篡改验证。系统入口要求已有受保护的 root 安装，当前安装器不创建它；详细边界见 [系统服务说明](SYSTEM-SERVICE.md)。公开仓库不包含本机 proof JSON、截图、日志、数据库或连接文件，运行对应测试可重新生成证明。

## 单标签页临时放行

按 [官方更新记录](https://getcoldturkey.com/news/) 中的未锁定、随机文本和密码三种方式补齐单标签页临时放行。官方未写明默认时长，本实现允许 1–1440 分钟，默认 5 分钟。授权按浏览器会话、标签页和规则隔离；只跳过该规则的网站拦截，不解除锁、不启动整条规则的休息、不放行应用或其他命中的规则。申请、到期、关闭、后台重启、锁与规则变更均有自动测试。

临时授权只存在后台内存，浏览器会话 ID 只放在扩展 session storage；磁盘缓存不保存授权或会话 ID。网络规则按各规则分别排除已授权标签页，不增加全局 allow 规则；内容脚本、嵌入页和使用统计仍经过相同的会话校验。密码验证沿用锁的失败等待，错误不会解除原锁。最多同时保留 512 个授权，到期后释放容量；旧后台或尚未更新的扩展不会显示不可用的按钮。Native Messaging 保留后台校验错误，避免把错误密码误报为离线。拦截页区分“仅当前标签页放行”和“整条规则休息”，弹窗显示当前标签页授权的剩余分钟。

`tests/integration_tab_ui.py` 启动隔离数据的真实后台，通过真实 Native Messaging 运行当前扩展 worker 与拦截页；浏览器 API 使用明确的测试替身。通过 Codex in-app browser 实际输入错误/正确文本和密码，验证错误被拒绝、只跳过对应规则、另一条规则继续拦截。同网址的第二个合成标签页仍受限；一分钟授权实际到期后重新检查恢复拦截，原文本/密码锁仍在。该测试不是已安装浏览器扩展或真实 DNR 执行证明。证据：`build/tab-ui-proof.json`、`build/Tab-only-other-blocked.png`、`build/Tab-only-password.png`。

真实 Edge 已成功重新加载已安装扩展：实际 DNR 重定向到拦截页，错误文本和错误密码被拒绝，正确验证后只恢复当前标签页。同网址另一标签页保持拦截；一分钟授权到期后，前台网页自动返回拦截页。新增第二条命中规则仍拦截已获第一条授权的标签页，单独放行未锁定的第二条规则后恢复访问。关闭该标签页，再以新标签页打开相同网址，仍被两条规则拦截。原锁一直保留。临时规则及本次创建的测试标签页已清理，用户原规则与设置摘要一致。证据：`build/edge-tab-proof.json`、`build/Edge-tab-expired.png`。

## 跨规则导入与慢启动恢复

在独立原生 QA 应用中，向锁定目标手工输入一个未保存网站，再进入导入窗口。选择后返回、Escape 和关闭按钮均回到原编辑器并保留草稿；取消整个编辑器不会保存草稿。多选两个来源的屏蔽网站，预览正确显示唯一项目和新增数量，保存后列表去重且原项目保留。也验证了从来源的网站例外列表复制到锁定目标的屏蔽网站，以及向未锁定目标的网站例外导入。仅包含既有项目时不会重复追加。来源规则在对应复制操作中保持原样；目标密码锁、应用和例外配置、原开启时间以及已花费的 30 秒额度均保留。证据：`build/import-ui-proof.json`、`build/Import-other-rules.png`。

复核中发现后台启动较慢时，原生壳约 9 秒后停止连接重试。现改为持续重试，等待较久后降至每 2 秒一次，并保持窗口可操作；日志超过阈值时保留末尾有限记录。`tests/integration_startup.py` 在独立副本故意将后台入口延迟 14 秒，原生日志确认越过旧上限后继续等待，后台就绪后原窗口自动加载，真实界面显示在线。测试记录与实际 API 均确认后台健康。测试不修改正式规则、注册信息或用户浏览器。证据：`build/startup-recovery-proof.json`、`build/Startup-recovered.png`。

## 未验证的能力

除 Steam 启动验证外，未在用户其他真实应用上测试强制结束；未触发真实锁屏、注销或关机；未停用原有 Cold Turkey；未验证 Safari、Firefox、Chrome、Brave、跨账号策略或系统级防篡改。功能表中的这些项目不能依据当前测试视为完成。

## Popup additions and interface sizing (0.3.0)

Final full regression: **214 Python tests** passed with bundled Python 3.13. The earlier system Python 3.9 run passed 213 tests; the added trailing-dot domain case was included in the final bundled run. Browser checks now total **121** (67 policies, 12 internal-page races, 17 tab grants, 14 popup additions, 11 sizing/persistence/coordinate checks).

The worker accepts website additions only from its own top-level popup, re-reads the active tab, and rejects requests after navigation changes. The backend validates HTTP/HTTPS and the settings password again. It only appends one target to an existing ordinary rule, without applications, exceptions, toggles or lock edits. Queries and fragments are omitted; paths with wildcard/control characters are rejected. Password checks share the existing retry delay, issue no general management session, and clear the input after submission.

`tests/integration_popup_ui.py` uses isolated data, a real backend and Native Messaging, and explicit browser API doubles. Actual Codex in-app browser interactions verified domain/path previews, locked additions, deduplication, exception warnings, wrong/correct settings passwords and additions to disabled rules without enabling them. Other rule fields and original runtime were preserved. Evidence: `build/quick-ui-proof.json`, `build/Popup-quick-add.png`.

The installed Edge extension was reloaded and its real toolbar popup used in a new test window. Adding the current domain to a temporary text-locked rule succeeded; submitting it again reported an existing target. The current page then automatically redirected to the block page. Opening the popup from that block page also previewed the original domain. The temporary rules were unlocked normally and removed; the user's original rules and settings matched the baseline exactly. Real Edge path-menu interactions were interrupted by window changes/native menu automation, so path mode is supported by the isolated UI evidence above, not claimed as a completed real Edge test. Evidence: `build/edge-quick-add-proof.json`, `build/Edge-quick-add.png`.

Sizing follows the [official text-size controls](https://getcoldturkey.com/support/how-to/change-text-size/), with an additional settings selector and zero-key reset. It uses a persistent 50–200% preference and respects settings authentication. Effective viewport sizing, compact navigation and scrollable dialog content keep the action footer visible. Calendar pointer coordinates are normalized to the displayed column height.

In the isolated browser, the selector set 150%, Ctrl-minus changed it to 140%, and a reload retained 140%. At 200%, the dialog and its save/cancel footer stayed within the viewport while the content scrolled. After enabling the test settings password, an unauthenticated reset was rejected and rolled back. In the real isolated `HotTurkey Quick QA.app`, Command-plus reached 110%, Command-minus changed 150% to 140%, star/zero reset to 100%, and the selector set 150%. Dragging Thursday at 150% saved 00:30–01:15 while the original Monday–Wednesday 09:00–10:00 entries remained intact. The QA app and its backend were stopped. Wheel/middle-button gestures have event tests but no native mouse-gesture test yet. Evidence: `build/native-text-size-proof.json`, `build/Text-size-200.png`.

## Protected kernel execution foundation (unreleased)

The current source additionally has a separately attested native session agent.
Run `python3 tests/integration_trusted_sessions.py` after the QA build for passive
console/foreground/idle sampling through real signed IPC, kernel audit-session
decoding, role separation, restart markers and wrong-server rejection. Local
GUI observations are recorded only as aggregate counts in ignored
`build/trusted-session-proof.json`; no app names, paths or installed rules are
published. This does not install a privileged daemon or prove real sleep/wake,
cross-account behavior or foreground allowance expiry.

Fifteen added unit tests cover trusted session roles, root-measured usage,
replay/concurrent agents, idle/console/gap transitions, account isolation,
kernel inventory freshness/identity, persistent login markers, monotonic caps
and strict background reward boundaries. The complete source suite now has
243 Python tests; browser checks remain 121. These counts describe the source,
not the unchanged v0.3.0 release assets.

The source now connects the experimental authority to an independent libproc-based executor. Fourteen new decision/lifecycle tests cover kernel-derived account contexts, selected/all-user scope, per-UID allowance ledgers, locked additions, protected paths, changing process identities, acknowledged statistics, malformed/oversized frames and authority shutdown on executor failure. Full local regression: **228 Python tests passed** with system Python 3.9.6.

`tests/integration_system_enforcement.py` was run with the app's bundled Python 3.13 and the current-UID-only native QA executor. It verifies actual kernel UID/PID data; wrong UID/generation rejection; the same PID replacing its executable without accepting a stale instruction; rejection of a malformed batch before any action; and the production executable refusing unprivileged launch. Real signed policy RPC drives the executor, including appending a unique binary target to a locked rule, SIGTERM termination, SIGKILL after a fixture ignores SIGTERM, unrelated fixtures surviving, successful-signal statistics, preserved lock/start state, executor-crash shutdown and authority restart with enforcement restored. The RPC also rejects direct kill commands and client-supplied usage/process samples. Evidence: `build/system-execution-proof.json`.

This uses disposable databases/sockets and test-created programs. It does not install a root daemon, modify the released current-user service, signal user applications or test a second real macOS account. Production helpers are packaged; QA binaries are excluded. Browser integration, session-agent supervision, device actions, complete manager APIs, privileged installation/migration and actual cross-account enforcement remain open. The system-mode component is not offered as complete anti-tamper protection; see [the current boundary](SYSTEM-SERVICE.md).
