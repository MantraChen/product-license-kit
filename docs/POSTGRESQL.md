# 异步仓储与 PostgreSQL

核对日期：2026-11-19。本文描述已合入 main 的源码 0.7.0，不表示已创建版本标签、发布 npm 包或完成生产部署。SQLite 当前迁移为 8；PostgreSQL 使用独立迁移 1–6、共 41 表。当前能力与外部验收边界见 [演进计划](ROADMAP.md)。

2026-11-19 集成复验：隔离 PostgreSQL 18.7 检查 109 项，默认回归 103 项。以下注明阶段的 19／37 等数量保留为历史证据；实际产品仍为 SQLite。

2026-11-18 工作区已实现 `AsyncStore`、`PostgresStore` 和 `AsyncFramework`，使用 node-postgres 8.23.1 的真实异步连接池。异步账号、订单、权益、付款异常、设备、许可证、分发、审计、分页和事务通知业务已接入现有 HTTP 参考接口。原同步 `Framework` 保留 SQLite API；EXAMBIA 产品仍使用该实现，尚未迁移生产数据库。

## 异步业务入口

```ts
import { AsyncFramework, PostgresStore, createApp } from 'product-license-kit';

const store = await PostgresStore.connect({ connectionString: privateDatabaseUrl });
const framework = await AsyncFramework.create({ store, catalog, signer, providers, issuer });
const app = await createApp(framework, { adminToken });
// catalog、signer、providers、issuer 和私有凭据由宿主显式准备。
try {
  await app.listen({ host: '127.0.0.1', port: 3100 });
} catch (error) {
  await app.close(); await store.close(); throw error;
}
// 正常停止时同样先 app.close()，再 store.close()。
```

`AsyncFramework.create` 在事务内初始化并验证已有权益／设备组与目录兼容。方法名、参数和返回数据与同步 Framework 对应，业务方法均须 await；不能将 PostgresStore 传入同步构造器。目录在创建时校验、复制并冻结，修改目录需要重新创建实例。可变业务参数在异步等待前取快照，避免调用方随后改动已验证内容。`accountEnabled` 仍是同步、只读、失败关闭的宿主策略。

每次公开业务操作在 SERIALIZABLE 事务内完成检查及效果；多步写入、命令结果、审计与 outbox 同时提交。领域层内部将其固定 SQL 转为 PostgreSQL 参数和表达式，不接受请求提供的 SQL。注册／登录的平台验证在数据库事务外执行一次；通用通知也在事务外发送，不能因数据库冲突重新发送外部请求。

宿主已有事务时，使用其 unit 创建限定入口：

```ts
await store.transaction(async unit => {
  const scoped = framework.using(unit);
  await scoped.grantCredits(accountId, 'desktop', 1, '人工核准', commandKey);
  await unit.run('UPDATE host_table SET reviewed=$1 WHERE account_id=$2', 1, accountId);
});
```

`host_table` 是宿主自己的表，框架不会创建。必须顺序 await scoped 方法；禁止在这种事务中注册、登录或发送通知。scoped 不负责自动重试，宿主须决定整个事务的重试和外部副作用边界。

## 连接与事务

```ts
import { PostgresStore } from 'product-license-kit';

const store = await PostgresStore.connect({
  connectionString: process.env.PRIVATE_POSTGRES_URL!,
  schema: 'plk',
});
try {
  const account = await store.transaction(async unit => {
    return await unit.get<{ id: string }>('SELECT id FROM accounts WHERE id=$1', knownAccountId);
  });
} finally {
  await store.close();
}
```

连接 URL 使用 postgres/postgresql 协议，须包含用户名、密码和数据库名，不接受查询参数覆盖 TLS 配置。仅 127.0.0.1、localhost、::1 的显式本机连接默认允许不加密；其他主机自动要求可信 TLS，始终校验主机名。`ca` 可提供独立 CA，包含证书的字符串仅用于该连接，不导入操作系统；显式空 CA 会被拒绝。库不记录 URL、密码、原始 SQL 参数或数据库错误详情。

`get<T>` 返回首行或 undefined，`all<T>` 返回行数组，`run` 返回 `{changes}`（pg 的 rowCount）。SQL 必须来自受控代码，参数使用 $1、$2；这不是接受用户 SQL 的沙箱。运行接口仅接受 SELECT、INSERT、UPDATE、DELETE、WITH 的单条语句，扩展查询协议拒绝多语句；事务控制和 DDL 由仓储内部处理。整数入参和 int8 出参均要求处于 JavaScript 安全整数范围，越界报错；不改 pg 的全局类型解析器。JSON 业务列保留文本格式，AsyncFramework 按共享领域模型解析。

事务默认 SERIALIZABLE。所有事务内查询必须使用回调传入的 unit，池级 facade 会拒绝从该回调发出的查询，避免跨连接。嵌套事务使用保存点，最多 16 层；父子或同级保存点不能并发交叉操作。必须 await 每次查询与嵌套任务，回调结束时仍有未完成任务则拒绝提交并丢弃连接。过期 unit 和超时后的继续执行不能重新使用连接。

| 配置 / 边界 | 默认值 |
| --- | --- |
| maxConnections | 10，允许 1–64 |
| connectionTimeoutMs | 10000，允许 100–60000 |
| statementTimeoutMs | 10000，允许 100–60000 |
| 客户端查询截止时间 | statementTimeoutMs + 1000 |
| transactionTimeoutMs | 30000，允许 100–120000 |
| 数据库事务内空闲截止时间 | 15000 |
| 池空闲连接保留 | 30000 |

事务截止时间包括回调及提交等待；建连另受连接截止时间控制。连接断开、未完成任务和超时会使连接失效。`stats()` 返回连接总数、空闲数、排队数、活跃事务数及连接错误计数，不返回业务身份。

## 失败与重试

`StorageError` 只保留安全错误码和可选 SQLSTATE。序列化失败／死锁返回 TRANSACTION_RETRY_REQUIRED，retryable=true；仓储不自动重跑回调。AsyncFramework 仅对自己拥有的、无外部 I/O 的业务事务进行最多三次尝试，覆盖序列化／死锁及唯一键竞争；重读状态后返回既有幂等结果或领域冲突，不重复付款、额度或审计。回调抛出的领域错误保留原对象，完成回滚后交回宿主。

COMMIT 回执丢失返回 TRANSACTION_COMMIT_UNCERTAIN；独立自动提交语句的回执丢失返回 POSTGRES_RESULT_UNCERTAIN。两者 retryable=false，不能据异常假设“没有写入”，应查询业务命令或记录核实。测试在真实数据库提交成功后注入回执丢失，确认数据已存在且回调只执行一次。TLS 校验失败单独返回 POSTGRES_TLS_FAILED，不降级为明文或关闭验证。

HTTP 会等待身份验证和所有写入完成后再答复。仓储失败返回 503 和脱敏错误；可重试冲突带 `retryable:true` 与 `Retry-After:1`。结果不明保留对应 UNCERTAIN 错误码并标记 `retryable:false`，不会建议盲目重放；SQLSTATE、SQL 和连接凭据不进入响应。

## 迁移与部署边界

PostgreSQL 使用独立的 `plk_pg_migrations`，迁移 1 建立对应 SQLite v7 领域布局的 19 张业务表及一张迁移表；迁移 2 追加三张协调表，迁移 3 追加签名钥、策略、计划及节点就绪四表，迁移 4 追加兼容导入记录，迁移 5 追加门户七表，迁移 6 追加 Bot 及注册交接六表，当前共 41 张表。迁移 1–5 摘要保持不变。迁移在数据库事务与按 schema 的 advisory lock 内执行；两进程同时启动只应用一次。每项保存 SHA256，已应用内容漂移、未来迁移或非本框架管理的已有表会拒绝启动，保留已有数据。

schema 默认 plk；名称只接受受限的小写标识符，拒绝 public、information_schema、pg_ 前缀。search_path 仅包含该 schema，pg_catalog 依照 PostgreSQL 规则隐式优先；不搜索 public。当前最低版本检查为 PostgreSQL 15，本地实际验证版本为 18.7。

默认 migrate=true 适合显式的初始化／升级身份。运行时可使用 migrate=false，仍检查完整迁移和摘要，不请求创建表。部署时使用单独的迁移身份；运行身份仅授予 schema USAGE、业务表必要 DML 及迁移元数据 SELECT。本次已验证只有 SELECT 的角色可检查既有迁移并读取数据，写入返回权限错误。未自动创建生产数据库、切换连接串或导入 SQLite／V5 数据；加密备份恢复见 POSTGRES-SIGNING；通用框架 SQLite v6/v7/v8 离线导入及切换封存见 [兼容迁移](SQLITE-POSTGRES.md)，实际生产切库仍须单独验收。

## 隔离验收

```powershell
$env:PLK_POSTGRES_BIN = '你的 PostgreSQL bin 绝对目录'
$env:PLK_OPENSSL = '你的 openssl 可执行文件绝对路径'
pnpm test:postgres
# 可选：同时构建并执行 C#／Rust 对真实 PostgreSQL 后端的回环 HTTP 验证。
# 需要 .NET 10、Rust 工具链；可通过 PLK_DOTNET、PLK_CARGO 指定私有工具。
pnpm test:postgres -- --native
```

脚本自行创建随机临时集群、随机 SCRAM 密码、仅本机回环监听及一天有效的 TLS 测试证书，测试后确认停止再清理该集群。不读取现有数据库 URL，不注册服务、不修改系统证书信任或 Hyper-V。Windows 默认可使用已安装 Git 的 openssl；其他环境通过 PLK_OPENSSL 指定。进程控制输出写文件，避免 Windows 后台进程继承管道导致启动等待不结束。

2026-11-18 异步业务首次接入阶段，本机 PostgreSQL 18.7 的 37 项仓储及业务检查在框架与产品 vendor 各自通过；两处默认回归各 91 项，产品生产构建及 458 项测试通过。PostgreSQL 检查覆盖双进程迁移、数据与整数精度、事务／保存点、并发余额、未等待任务、截止时间、丢失回执、活动及空闲连接断开、TLS 和最小权限角色，并执行与 SQLite 共用的九组业务／HTTP 契约。附加业务检查覆盖两个实例竞争命令／付款／额度、付款与异常流水互斥、邀请消费、宿主事务回滚、有限重试、禁止重放结果不明、脱敏响应、可变输入快照、资源写入失败回滚及既有记录的启动兼容性。

C# 76 项、Rust 77 项真实 HTTP 检查另在该异步 PostgreSQL 后端通过，覆盖 Ed25519／RSA-PSS 激活、签发、范围／时间拒绝、挑战重放、分发验签和退出。Windows DPAPI 双向互读仍通过。检查使用随机本地身份和合成付款，没有调用支付平台或发送真实消息。

后续已补 [共享限流、任务租约与通知 worker](COORDINATION.md)，以及 [共享签名策略、自动计划和加密恢复](POSTGRES-SIGNING.md)。AsyncFramework 的新通知使用持久队列，发送结果不明进入核销；SQLite 的旧 dispatcher 仍为单 worker。通用框架现已提供 [SQLite v6/v7/v8 离线导入](SQLITE-POSTGRES.md)，仍不包含 V5 数据导入或产品生产切库，不能把通用框架验收视为产品多节点部署通过。

依据：[node-postgres 事务](https://node-postgres.com/features/transactions)、[连接池](https://node-postgres.com/features/pooling)、[TLS 配置](https://node-postgres.com/features/ssl)、[PostgreSQL 隔离级别](https://www.postgresql.org/docs/18/transaction-iso.html)。
