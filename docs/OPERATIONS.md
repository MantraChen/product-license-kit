# 部署与维护

文档分工核对：2026-11-19。本页负责部署、备份、迁移及密钥；跨步骤状态与异常处理见 [详细契约](CONTRACTS.md#5-分发通知与迁移)。适用于源码 0.7.0；历史迁移编号与发布事实按原日期保留。

## 0.7.0 升级说明

2026-11-12 的 0.7.0 Beta 商品变更没有引入迁移。当下 main 仍标为源码 0.7.0，但随后已追加 SQLite 迁移 7（事件资源）和 8（同机任务）；PostgreSQL 使用独立迁移 1–6、共 41 表。按固定提交升级，不能仅凭 package 版本判断 schema。Beta 商品配置新增 kind=channel、channel=beta 与 requiresChannel=beta；旧消费者若使用严格商品 schema，须和服务端一起更新。设备 RSA-PSS 支持不改变 Ed25519 服务器信任根，不能替换客户端预置签名公钥。升级前仍须备份并核对权益与付款来源。


## 本地配置

`pnpm run init:local` 生成本地随机凭据和 Ed25519 签名密钥。只运行一次；重新初始化会拒绝覆盖。`.env.example` 中的占位密钥不能直接启动服务。首版要求 Node 24.19+ 的 24.x 系列。

运行 `pnpm start` 时 Node 读取 `.env`。首次启动创建 SQLite 数据库，启用外键、WAL 和五秒 busy timeout。每分钟清理过期的会话、挑战和邀请；订单、审计、分发和幂等记录不自动删除。

## 生产接入前

- 使用真实身份适配器，删除本地身份配置并设置 `NODE_ENV=production`。生产模式会拒绝本地开发身份验证器。
- 通过 HTTPS 反向代理暴露公共 API，管理路由限制为受控网络或管理网关。默认监听 `127.0.0.1`。
- 为人工管理界面接入 SSO/MFA、具体操作员身份和权限分离。框架根密钥只能留在管理后端。
- 默认 `trustProxy=false`，防止直接信任伪造 IP 头。可设置 `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128`，仅填写实际可信反向代理地址；不允许 `true`、任意跳数或 `/0`。已测试非可信来源的伪造转发头不会改变客户端 IP。
- 设置密钥文件和数据库的最小文件权限；Windows 部署使用 ACL，不能假设 Unix `0600` 等价生效。首版提供文件密钥参考实现，未集成 KMS/HSM。
- 同步 outbox 由单 worker 调度；异步 PostgreSQL 可显式启用持久通知 worker。配置退避、停发与结果不明核销，不因库升级自动启用真实发送。
- 不向客户分发任何能控制服务器的管理员密钥、支付密钥或 Bot token。

## 配置与升级

目录中的产品、版本和设备组 ID 是持久标识。已发权益所引用的版本、已有绑定所引用的组不能直接从目录移除，服务启动会拒绝这类配置。产品转组、重新定义版本归属、合并账号等变更仍需显式迁移，不通过简单改 JSON 隐式完成。

已创建订单保存价格和资格快照。调价影响后续新订单；旧订单按快照核实。当前版本使用 order_deadlines 记录截止时间并派生过期状态；过期付款需显式复核，不能将超期等同未收款。运营方仍可取消符合条件的待支付订单。订单、已完成且仍有权限的分发和管理审计已有游标分页；每页最多 100 条，无查询参数保留最近 100 条数组兼容响应。

0.1.1 增加 `plk_migrations` 第 2 版与 `account_states` 表，保留旧 `accounts` 列布局和既有数据；重复启动不会重复迁移。升级前先备份；后续 schema 变更继续使用显式迁移，禁止删库重建生产数据。

0.2.0 的迁移 3 将 `entitlements.order_id` 改为可空，并增加 `entitlement_imports` 与 `entitlement_channels`；保留原有付款授权和订单。升级后核对来源、渠道和既有权益。降级必须恢复与旧代码匹配的备份，不能仅回退可执行文件。

## 备份与恢复

从 0.1.1 开始，已有本地环境运行 `pnpm security:protect-local` 收紧仓库、`.env`、`.data` 的权限。Windows 保留当前身份、SYSTEM、Administrators，Unix 目录 0700 / 私有文件 0600。以实际服务身份执行；不要对共享驱动根目录运行。自定义数据目录可调用 `privateDirectory` / `protectPrivatePath`。已单独保护的子文件应递归检查。

停止服务后，将至少 20 字符的随机恢复口令保存在受限文件，口令与导出的备份分别保管。不要在命令参数中填写口令本身：

```sh
pnpm maintenance backup /private/recovery-password.txt /private/backup.plkbackup
pnpm maintenance restore /private/recovery-password.txt /private/backup.plkbackup /private/new-restore-directory
pnpm maintenance rotate-signing /private/recovery-password.txt /private/before-key-rotation.plkbackup
```

快照包含已提交的 WAL 数据；加密包使用带认证的 AES-256-GCM 和 scrypt 派生密钥，当前工具限制原始文件总量 256 MiB。恢复先验证认证标签与文件名，仅允许新目录，绝不覆盖活跃数据库。恢复目录的 `environment.env` 是配置备份，应检查其中路径再用于部署。签名轮换先自动备份，保留旧公钥历史；新公钥仍必须经可信发布流程分发给客户端。

单进程服务锁阻止重复运行；维护工具拒绝在服务进程存活时执行。异常断电若留下 `.guard` 文件，应确认没有进程正在启动后人工处理，不能直接忽略锁。

最简单的受控备份方式是停止服务、确认连接关闭，再复制数据库与私有签名密钥到加密备份存储。在线备份应使用 SQLite 的一致性备份机制；不能只复制正在写入的主数据库文件而忽略 WAL。

恢复时校验应用版本、schema、目录配置和签名密钥对应关系，在隔离环境验证账号、订单、权益、换绑时间、额度和分发记录。避免把备份恢复到公开 demo 环境。

## 密钥轮换与永久授权

同步参考部署使用部署签名密钥；可选 PostgreSQL 服务另有共享策略、节点就绪证明和指定轮换计划，见 [签名计划](POSTGRES-SIGNING.md)。轮换需先通过可信更新让客户端信任新公钥，再切换签发端，按旧许可证寿命完成过渡。不要在没有客户端更新和回退方案时直接删除旧密钥。

永久权益与持续服务能力不是同一承诺。对外产品需说明离线期限、停服恢复、版本下载保留和许可证刷新策略。这些运营决定不能由短期 token 的实现代替。

## 当前部署与外部验收

PostgreSQL、游标分页、多节点限流与任务租约、指定签名计划、门户 MFA／具名权限、通用 Bot 及 Windows C#／Rust 软件身份 SDK 已有本地实现。真实商户回调／退款／对账、实际文件上传与对象存储、Authenticode、产品 TPM、目标主机恢复与监测仍需宿主接入和验收。框架不自动创建异地备份或告警接收目标。完整状态见 [演进计划](ROADMAP.md)。

2026-11-19 集成本地检查为默认 103 项、隔离 PostgreSQL 109 项，demo 与 140 文件源码审查通过；远端 Windows／Ubuntu Actions 因计费锁定未启动。源码合并不等于已部署。

0.3.0 的迁移 4 增加 binding_resets，以账号和设备组关联现存绑定，保存一次重置后等待重新绑定的代次。它保留现有绑定、订单和额度；重启不丢失待绑定状态。重置和后续激活都在事务内执行。升级前备份，降级恢复对应备份。

## PostgreSQL 与同机任务维护

PostgreSQL 部署使用受限运行角色与独立迁移角色，远端连接校验 TLS；通过 `pnpm start:postgres` 启动参考服务。共享 namespace、限流 secret、签名上下文及节点私钥须一致审核，自动轮换缺省关闭。备份需覆盖门户加密钥与签名钥，恢复只进入空 schema；详细命令见 [签名与恢复](POSTGRES-SIGNING.md)。

通用 SQLite v6/v7/v8 离线切库按 [导入流程](SQLITE-POSTGRES.md) 审核摘要、备份、锁源、封存及独占目标，不导入 EXAMBIA／V5 表。SqliteTaskQueue 的多进程仅共享同一主机的私有库；维护时同时停止所有写入者。任务记录、幂等与审计不适用产品个人 EXE 七天清理期限。
