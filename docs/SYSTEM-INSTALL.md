# 系统安装准备与当前边界

当前只提供可检查的安装材料和安装基础组件，**不是可用的生产系统安装器**。`scripts/prepare_system.py` 由普通账户运行，不申请管理员权限，不停止后台，不读取正式规则，不写系统目录，也不加载任何服务。当前用户版安装器保持原有行为，存在锁定时仍拒绝更新。

系统后台与交互会话代理使用不同的 launchd 计划，符合 Apple 对 [daemon 和 agent 职责](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)的区分。分发安装包所需的 Developer ID Installer 签名和公证仍缺失；参见 [Apple 分发说明](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)。安装材料清单只提供完整性检查，不充当发布者签名。

## 准备和检查

先构建包含独立运行时的正式应用：

```sh
python3 -B scripts/build.py --qa
```

在构建目录创建浏览器输入 JSON，明确指定本机实际浏览器及已安装的 HotTurkey 扩展来源。例如 `build/browser-input.json`：

```json
{
  "Edge": {
    "app": "/Applications/Microsoft Edge.app",
    "origins": ["chrome-extension://请替换为实际32位扩展ID/"]
  }
}
```

此示例必须替换为真实扩展 ID 才能通过校验。Firefox 来源使用 `hotturkey@local.hotturkey`。工具核验所选浏览器的 bundle ID、开发者签名和实际 designated requirement，并只允许列出的扩展来源。该步骤没有安装扩展、修改浏览器或配置扩展防篡改策略。

```sh
python3 -B scripts/prepare_system.py --browser-config build/browser-input.json
python3 -B scripts/prepare_system.py --inspect build/protected-payload
```

管理账户默认取执行准备工具的本机 UID，也可显式传入 `--controller-uid`。输出目录必须不存在，工具不覆盖已有材料；可以用 `--output` 为另一份材料指定新目录。不要使用 sudo 运行准备工具。

准备后的材料包含：

- 重新密封 `HotTurkeySystemMode=true` 的正式应用，生产代码和独立 Python；测试应用、测试执行器及外部 Python 被拒绝。
- 从签名应用提取的五个原生助手，以及按实际代码哈希区分的管理、会话和浏览器角色。没有加固运行时或带调试、动态库验证例外的角色被拒绝。
- 固定程序路径的策略配置、浏览器配置、后台与会话启动计划。Python 使用 `-I -B`，启动入口只添加固定受保护的源码目录；不从当前目录或用户环境导入程序。
- 文件类型、大小、权限、SHA-256 和内部链接清单。拒绝越界/目录链接、硬链接和特殊文件。即使重写清单，也不能把修改过的外部助手、策略代码或启动入口伪装成签名应用中的原件。

预定系统路径是 `/Library/PrivilegedHelperTools/local.hotturkey`、`/private/var/db/local.hotturkey`、`/private/var/run/local.hotturkey`，以及两个固定 launchd plist。准备工具仅将这些路径打印出来。

## 数据迁移与文件事务

`system_migration.py` 先通过不跟随链接的文件描述符，将源数据库及 WAL 复制到私有临时目录，再让 SQLite 打开私有副本。拒绝错误所有者、宽松权限、硬链接、特殊文件、复制期间变化、未知表/视图/触发器及无效策略 JSON。原数据库不执行迁移、不修改策略。

迁移副本保留规则、设置密码和安全词摘要、统计、休息状态、自动启动记录和已消耗额度；额度按管理账户 UID 转入共享策略，只做一次前缀转换。复制现有系统数据库时不能更换管理账户。任何仍生效的锁都会阻止迁移，包括定时锁、当前启动的重启锁及自动设备日程锁。正式服务必须先安全停止，再复制；当前组件不会替调用者停止服务。

`system_transaction.py` 为调用者预先确定的文件目标提供受保护祖先检查、互斥锁、同目录原子改名和先写入再同步的事务日志。提交前中断可逆序恢复原文件；提交点持久化后只完成备份清理，避免回退已经启用的新数据。恢复时目标必须与调用者的固定路径映射完全相同，日志不能提供任意文件路径。它是文件事务组件，不负责服务状态或授权。

## 尚待完成

正式安装协调器仍需连接：运行时管理授权、锁定检查、旧服务停用与复查、私有暂存、固定目标发布、新服务健康检查及提交点，以及进程/断电中断后的服务状态恢复。切换期间还必须防止新旧后台同时执行，或让新后台接受的规则/额度更新被回退覆盖。

浏览器全局 Native Messaging 注册、每用户旧连接的切换、桌面默认入口、现有登录项和多账户代理部署也未接入。它们不能只靠复制文件完成。系统卸载需经过管理验证和锁定检查，并明确保留数据和恢复当前用户版的方式。

上述流程准备完整并可审查后，才适合请求真实系统安装授权。当前没有写入 root 安装路径；真实登录、跨账户、睡眠/唤醒、系统保护与新机器安装仍不成立。

## 验证

```sh
python3 -B -m unittest discover -s tests -v
python3 -B tests/integration_system_package.py
```

单元测试覆盖清单篡改、签名角色、路径/权限、WAL 数据保留、旧库不变、迁移幂等与锁定拒绝，以及改名/日志/提交清理中断后的文件恢复。真实签名集成使用一次性材料和测试代码，验证签名应用、实际角色代码、调试例外拒绝及独立 Python 不读取用户环境；不启动系统后台，也不修改正式用户规则。
