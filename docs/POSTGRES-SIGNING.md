# PostgreSQL 签名轮换与加密恢复

面向维护框架异步部署的操作员。2026-11-18 工作区新增共享签名策略、指定公钥计划、节点就绪证明、持久执行租约、加密备份和只向空 schema 恢复的工具。SQLite 产品保留自己的监督进程方案；本页不表示 EXAMBIA 已切换数据库或正式 Windows EXE 签名完成。

## 启动与私有配置

运行 `pnpm build`，将 `PLK_POSTGRES_CONFIG_FILE` 指向源码外的私有 JSON，再运行 `pnpm start:postgres`。入口为 `examples/postgres-server.mjs`，连接、私钥、管理员令牌、身份及备份密码均不来自 HTTP 计划。私有配置路径以配置文件目录为基准解析；私有文件会核对链接并设置权限。

```json
{
  "connectionString": "替换为私有 PostgreSQL 连接串",
  "schema": "plk",
  "caFile": "server-ca.pem",
  "migrate": false,
  "host": "127.0.0.1",
  "port": 3100,
  "nodeEnv": "production",
  "issuer": "your-product",
  "nodeId": "node-a",
  "contextHash": "替换为64位小写SHA256部署摘要",
  "adminToken": "替换为独立随机管理员令牌",
  "rateLimitSecretFile": "rate-limit.key",
  "catalogPath": "catalog.json",
  "keyFiles": ["current.pem", "next.pem"],
  "enableKook": true,
  "rotationEnabled": false,
  "backup": {"directory": "backups", "passwordFile": "backup-password.key"}
}
```

先用有迁移权限的独立身份初始化／升级，再将 `migrate` 设为 false，使用必要 DML 权限运行。远程 PostgreSQL 强制 TLS 及主机名校验；CA 不写进系统信任。管理员令牌和共享限流秘密至少 32 字符，备份密码为 20–256 字符。节点共享 schema、issuer、限流秘密、部署摘要及信任配置，各自使用固定的 nodeId。部署摘要应来自已核对的发行、目录和客户端信任材料；它不是客户端自报信息。

`keyFiles` 首项是初始化时正在使用的 Ed25519 私钥，后续项是提前安全分发的候选钥，最多 31 项以满足备份文件数量上限。私钥不经计划接口上传。生产需要真实身份提供方；只有 development 可另配 `localIdentityPath`。默认自动执行关闭；开关为 true 时必须配置可用加密备份。所有节点启动后会为已配置候选钥刷新就绪证明；允许多个控制节点竞争同一计划。

签发节点对签名钥、策略和计划只需 SELECT；为取得共享行锁，可仅给策略及计划表 `UPDATE(updated_at)` 列权限，加上节点就绪表必要 INSERT／UPDATE。控制节点另需策略初始化、计划管理及启用钥／epoch 更新权限。不要为签发节点整表开放策略更新。该最小列权限已经真实角色验证，规则依据 [PostgreSQL SELECT 权限](https://www.postgresql.org/docs/18/sql-select.html)。

## 初始化与创建计划

管理入口均在 `/v1/admin`，需要管理员 Bearer 令牌，拒绝带 Origin 的浏览器请求。浏览器门户须通过自己的同源 BFF／MFA／操作员策略调用，不向网页暴露该令牌。

显式配置部署摘要后，策略尚未初始化或记录缺失时拒绝签发，不回退到进程主钥；管理入口仍可用于完成初始化。

| 方法 | 路径 | 输入／结果 |
| --- | --- | --- |
| POST | `/signing/policy` | `{activeKid,requiredNodes,actor,reason}`，首次明确登记当前钥、固定节点集合和部署摘要；不通过重复初始化切换已有策略。 |
| POST | `/signing/rotations` | `{publicKey,notBefore,expiresAt,actor,reason,clientsReady:true}`，仅接受公开 SPKI PEM，时间为整数毫秒。 |
| GET | `/signing` | `{plan}`，优先返回当前活动计划，否则返回最近历史；无计划为 null。 |
| GET | `/signing/rotations/:id` | 指定计划，跨 namespace 或不存在为 404。 |
| POST | `/signing/rotations/:id/pause` | `{actor,reason,revision}`，旧页面代次拒绝；暂停不启用或回退密钥。 |
| POST | `/signing/restore-review` | `{actor,reason}`，停服恢复后暂停未完成计划并清除其节点就绪证明。 |

计划开始至少在数据库当前时间一秒后、最多一年后，窗口最长一天。一个 namespace 只能有一项 scheduled／running 计划。候选公钥注册后不可替换其对应内容；旧公钥保留。`clientsReady:true` 是管理员已核对双公钥信任、实际客户端构建及分发的记录，不证明所有用户已经升级。框架不会通过公钥接口自动扩大客户端信任。

## 节点证明与执行

`PostgresSigningCoordinator.acknowledge` 用候选私钥签署专用 `plk-signing-ready` 信封，绑定计划 ID、namespace、当前 epoch、节点、候选 kid、部署摘要、随机 nonce 和期限。它不是许可证。证明最长五分钟，默认两分钟；窗口到期、内容改变、缺钥、旧节点或失效证明均不满足执行条件。

到窗口后，数据库行锁只允许一个控制进程进入 running，并取得随机持有者及默认 90 秒租约；处理时续租。备份在业务事务外执行，默认截止 30 秒、最多 60 秒。备份失败、超时或持有者丢失后暂停，不自动重复外部工作。进程退出留下的 running 租约到期也只暂停；重新核查后创建新计划，不复活旧尝试。还未到窗口的计划保持 scheduled，过期计划变为 expired，不在任意以后时间补做。

备份完成后，在一个 SERIALIZABLE 事务中重新核对原钥、epoch、部署摘要、节点集合、全部证明、租约和时间；随后同时切换 active_kid、递增 epoch、记 completed 及写审计。审计失败整体回滚。COMMIT 回执不明不重跑备份或启用，先查询计划和当前公钥。没有自动降级／回退到旧钥。

若备份已核对、后续启用失败且持有者仍相符，暂停时保留备份回执并另记审计，便于定位已生成的私有恢复包；失去持有者的进程不能修改后来状态。

AsyncFramework 每次签发新许可证或分发清单时按共享策略选钥，并持有策略行共享锁至业务事务提交。启用动作等待进行中的签发；已开始事务若快照过旧则按原规则重试。缺少活动私钥或部署摘要不符时返回 503，拒绝继续用旧钥签发。`/v1/signing-key` 返回当前启用的公开材料；`framework.signer` 仍表示构造时的主钥，宿主代码应使用 `currentSigningKey()` 查询异步运行状态。已 finalize 的旧清单保持不可变，旧许可证仍按原有效期及预置信任验证；部署不能继续运行绕过该策略的旧二进制。

## 备份与恢复

`backupPostgres` 以 SERIALIZABLE 快照分批读取框架精确表集合，保留当前迁移版本及摘要，最多 250,000 行、256 MiB 原始内容；未知宿主表或变动列／类型拒绝备份，避免静默漏数据。框架数据和所需私钥使用现有 AES-GCM 备份格式加密到新私有文件，重新读取并解密核对后才发回回执。回执只含计划绑定、加密包 SHA256、随机参考号和验证时间，不含密码、私钥或文件路径。历史包不会自动删除，应按宿主备份保留策略处理。

`restorePostgres` 只接收初始化后所有框架业务表均为空的目标 schema，先核对密码、迁移摘要、表列、密钥材料，并要求操作员为每个 namespace 明确提供允许恢复的 active kid 和部署摘要。不同的现役钥不能通过旧备份被隐式回退。整批导入和恢复审计同事务提交；拒绝覆盖已有业务。

恢复审计关联输入加密包 SHA256；暂停任务及计划的更新时间使用实际恢复时间，原创建时间和历史审计保留。

恢复清除会话、邀请、挑战及节点就绪；未完成轮换暂停；pending／leased／sending 外部任务转 uncertain、清除租约并递增代次，不能自动重发。未到期的旧限流预算填满至窗口结束。权益、付款、设备、冷却、额度和既有审计保留。恢复工具不启动服务、不自动写回私钥文件；操作员须把确认过的密钥、私有配置及备份口令按部署方案放回，并核销外部结果后启用 worker。此格式不是 SQLite／V5 数据迁移器，也不代替目标服务器的恢复演练。

## 本地验证

`pnpm test:postgres` 在随机本机 PostgreSQL 18.7 集群执行；迁移 3 新增四表，迁移 4 追加兼容导入记录，迁移 5 追加门户七表，当前共 35 表。迁移 1–4 摘要保持不变。专项包含两个独立控制进程唯一启用／唯一加密备份、真实参考服务的管理 HTTP 与自动执行、真实签发中的切换、备份途中到期、超时、旧持有者、审计回滚、丢失提交回执及加密空库恢复。完整 SDK 回归可用 `pnpm test:postgres -- --native`。

最终框架及产品 vendor 各通过 63 项真实 PostgreSQL 检查和 96 项默认回归。签名专项还覆盖超出初始租约的真实长备份持续续租、受限角色不能修改启用钥、备份目的地输入快照及未知宿主列拒绝。C# 30 项本地／76 项 HTTP、Rust 五项测试／77 项 HTTP 检查通过。产品生产构建及 481 项回归通过。以上都是本地合成数据检查，未修改产品部署、启用实际换钥或进行生产个人 EXE 的 TPM 操作。

SQLite 兼容导入另见 [离线迁移](SQLITE-POSTGRES.md)。目标存在 pending 导入记录时，新运行连接及重建连接都拒绝服务；维护身份可核查。备份包含兼容导入历史；恢复后 pending 仍保持阻止服务，不会隐式解除封存。

后续迁移 5 另加入门户七表，当前 35 表；迁移 1–4 摘要保持不变。存在门户 namespace 时，加密备份必须通过 `portalKeys` 提供每把独立门户钥，缺钥拒绝；恢复清除所有浏览器会话、OAuth state 与换绑意图，保留 MFA 和角色。详见 [门户恢复](PORTAL.md#备份与恢复)。
