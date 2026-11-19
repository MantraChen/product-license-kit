# PostgreSQL 多节点协调

2026-11-18 工作区提供共享限流、持久任务队列及通知 worker。它们使用同一个 PostgreSQL schema 和数据库时钟；没有把产品 EXAMBIA 的 SQLite 部署切换为多节点。旧同步 Framework 的通知 dispatcher 仍按单 worker、至少一次投递使用。

## 共享 HTTP 限流

后续 [PostgreSQL 签名计划](POSTGRES-SIGNING.md) 为签发增加共享 active kid／epoch、候选节点证明、计划租约及加密恢复；参考服务同时接入本节共享限流。新增迁移 3 不改变迁移 1／2，该阶段共 27 表；当前已追加至迁移 6、共 41 表，见 [当前存储布局](POSTGRESQL.md)。SQLite 适配仍使用自己的迁移编号。

```ts
import { PostgresRateLimiter, createApp } from 'product-license-kit';

const sharedRateLimiter = new PostgresRateLimiter(store, {
  namespace: 'license-api',
  secret: privateSharedRateLimitSecret,
});
const app = await createApp(asyncFramework, { adminToken, sharedRateLimiter });
```

各节点必须使用相同 schema、namespace、私有 secret、路由及限流参数。secret 为 32–256 字符，在私有部署配置中共享，不能传入浏览器或放进仓库。数据库仅保存 HMAC-SHA256 键，不保存原始 IP；这仍是需要保护的运行数据。更换 secret 或 namespace 会建立新预算，不能滚动混用新旧值，否则预算会被拆分；应停发并统一切换。

沿用 Fastify 对可信代理和 IPv6 的 IP 键规则。默认全局每分钟 120 次；登录和注册分别使用各自每分钟 10 次的路由预算，与原参考接口相同，路由预算替代该路由的默认预算。自定义身份组、账号或其他操作可直接调用 `increment(key, windowMs, max, scope)`。固定窗口从该键第一次请求开始，以数据库时钟判定；计数最多记到 max+1。`read` 不增加计数，`cleanup(limit=1000)` 按数据库到期时间有界清理。

相同键的 windowMs 或 max 不一致会失败关闭；不悄悄采用某个节点的参数。过期后清理旧桶，再统一部署新策略。自定义 Fastify store 不支持 continueExceeding 或 exponentialBackoff；会拒绝这些选项。数据库不可用或回执不明时返回 503，不降级为节点内存放行。未传 sharedRateLimiter 的旧部署继续使用原内存限流，不能据此宣称有跨节点预算。

## 任务与租约

```ts
import { PostgresTaskQueue } from 'product-license-kit';

const queue = new PostgresTaskQueue(store, { namespace: 'artifact-build', leaseMs: 90000 });
await queue.enqueue({ key: distributionId, payload: { distributionId }, maxAttempts: 6 });
const lease = await queue.claim();
if (lease) {
  // 先做可重复的准备工作；耗时任务必须周期调用 heartbeat(lease)。
  const result = await prepareArtifact(lease.payload);
  await queue.complete(lease, result);
}
```

示例中的制品准备由宿主实现，队列本身不会生成、签名或发布文件。任务 key 在 namespace 内唯一；相同 JSON 内容和调度参数重放返回原任务，不重新启动已完成工作；冲突不覆盖已有 payload。JSON payload 和 result 各最多 16 KiB，建议只放资源 ID，秘密和大文件保留在私有存储。默认最大六次尝试、24 小时 TTL、无延迟；TTL 允许 1 秒至 30 天，延迟必须短于 TTL，最大尝试数为 1–100。

`enqueue` 可使用显式事务 unit 创建的 queue，与宿主业务记录同时提交；不能在该 unit 上执行 worker 的 claim、心跳、外部开始或完成等方法。任务领取使用一条 `FOR UPDATE SKIP LOCKED` 更新，得到随机 token 和递增 generation。所有状态变更检查 namespace、ID、token、generation、当前状态、数据库租约和 TTL。过期 worker 的完成、失败、续租及外部开始都会拒绝。

`claim({keys})` 可将一次领取限制在最多一百个任务 key 中；空列表不领取任何任务，不提供列表时保持原有全命名空间领取。列表仅作为参数值参与 SQL，不接受查询片段。`release(lease, unit?)` 只允许归还尚未进入 sending 的有效 leased 任务，将本次领取增加的尝试次数退回；可在宿主事务内与路由核对一起提交或回滚。下一次领取仍增加 generation，旧 token 不能完成任务。sending、结果不明及过期租约不能借此恢复待发送。队列原有的 TTL 与过期租约 sweep 仍适用于整个命名空间。

租约默认 90 秒，可配 100 毫秒至 15 分钟；准备阶段 `leased` 过期可重新领取，attempts 与 generation 增加。`heartbeat` 只能延长当前仍有效的租约，不能复活过期 token。达到次数上限进入 dead，TTL 到期进入 expired；`sweep` 和领取均有批量边界。失败重试按 1 秒、2 秒、4 秒等递增，封顶一小时，并受 TTL 和次数限制。`list` 支持每页 1–100 条、按创建时间与 ID 倒序的游标，绑定 namespace 和状态；列表不暴露租约 token。

## 外部副作用

```ts
const sending = await queue.beginExternal(lease);
try {
  const receipt = await sendToVerifiedReceiver(sending.payload);
  await queue.complete(sending, { receipt });
} catch {
  await queue.fail(sending, 'EXTERNAL_RESULT_UNCERTAIN');
}
```

先持久化 sending，再调用外部服务。sending 租约过期、进程崩溃或发送结果不明会进入 uncertain，禁止自动重领。不能用“本地没有收到成功响应”证明对方没有接收。只有明确证明未被接收时，才能用 `fail(lease, code, {retryable:true, definitelyNotSent:true})` 安排退避重试。错误码仅接受受限的大写标识符，原始异常、连接串和平台响应不写进任务错误。

这不是外部“恰好一次”保证。外部平台若有持久幂等接口，应同时使用任务 ID。发送超时后非协作的 sink 仍可能完成外部请求；任务保持 uncertain，不能因此重发。恢复旧备份可能丢失备份后的副作用记录，恢复后必须先停发、核对并隔离历史未结任务，再启动 worker；租约不代替恢复核销。任务及幂等元数据当前不自动删除，不能套用个人 EXE 七天清理规则。

## 通知接线与核销

AsyncFramework 的新 outbox、资源引用和通知任务在同一业务事务内生成。迁移 2 增加 task_jobs、task_job_reviews、rate_limit_buckets，不改迁移 1 摘要、不重建业务表，不为历史 outbox 猜测任务。迁移后共 23 张表，含一张迁移表。历史通知是否重放仍由宿主明确核准。

`AsyncFramework.dispatchNotifications(sink, limit)` 已使用该持久 worker，保留 `{delivered,failed}` 返回结构。需要详细状态时直接创建 `PostgresNotificationWorker`，`run` 返回 delivered、failed、skipped、uncertain。多个独立进程可同时领取。worker 在发送前重新核对账号状态、当前外部身份和精确资源引用，可叠加宿主账号策略。暂停账号的通知不会到达 sink。

同一库包含不同身份平台时，独立平台消费者必须明确设置 `providers`，例如 `new PostgresNotificationWorker(store, {providers:['kook']})`；另一个平台使用自己的 provider 名单。名单为一到三十二个格式有效的标识，复制保存，修改调用方数组不会改变正在运行的 worker。候选选择有一百项上限，最终领取仍受统一租约与 fencing 约束。其他平台的未过期任务保持未领取，尝试次数不增加；候选读取后或准备期间身份改变时，发送前重新读取并归还尚未发送的任务，不使用旧收件人。已进入 sending／uncertain 的任务不能因平台变化而重发。

省略 providers 的旧 dispatcher 仍接收全部平台，适用于统一路由 sink，不能把不识别其他平台的单平台 sink 当成统一路由。平台名单是自动任务路由条件，不是操作员权限边界；`resolve` 保留可信宿主的人工核销契约，宿主必须核实权限及当次发送的历史平台／收件证据，不能凭账号当前平台推断旧消息的接收方。跨平台查询与本地事务不能原子提交，准备检查之后的外部在途变化仍需按发送结果不明规则处理。

worker 默认 8 秒发送截止时间、90 秒租约，并在处理时续租；截止时间可配 100 毫秒至 60 秒。已确认未接受的 sink 可抛 `NotificationNotSentError` 安排重试；普通异常保守归为结果不明。KOOK 通用 sink 未提供可证明“未接受”的专门回执分类，因此其发送异常保留核销，不依据 HTTP 成功页、截图或本地超时推断状态。产品专用通知账本继续使用自己的平台判定流程。

接受回执后，任务成功与 outbox.delivered_at 在同一事务提交。发送前状态事务及发送后的回执事务仅对数据库序列化／死锁进行最多三次尝试；不重跑发送。COMMIT 结果不明不自动重试，后续通过任务及平台证据核实。

```ts
const task = await worker.queue.get(eventId);
await worker.resolve(eventId, {
  outcome: 'succeeded',
  actor: verifiedOperatorId,
  generation: task.generation,
  reason: '已核对平台接收记录',
  result: { receipt: verifiedReceiptId },
});
```

宿主必须先验证操作员权限和证据。`worker.resolve` 同时提交任务、核销审计和 outbox 回执；通用 queue.resolve 不负责业务表，应只用于其自身任务。核销要求 actor、原因及当时 generation，旧页面不能核销后来的尝试。结果可为 succeeded、cancelled 或 retry；retry 另须 confirmedNotSent:true，且任务仍在 TTL 内。核销结果与 task_job_reviews 原子提交，审计失败即整体回滚。此工作区未给产品管理页面新增 PostgreSQL 任务界面，也未自动启用任何真实发送。

## 本地实测

通过 `pnpm test:postgres` 使用自建随机本机集群。覆盖独立 Node 进程的共享 12 次预算、20 任务竞争、发送前后进程退出、过期 token 拒绝、退避／次数／TTL、分页、心跳、超时、接收后回执丢失、人工核销及审计失败回滚。两个通知进程向真正的回环 HTTP 接收器投递十条合成事件，逐条核对唯一接收；没有连接 KOOK 或支付平台。

该阶段框架及产品 vendor 分别通过 52 项 PostgreSQL 检查与 91 项默认回归。主框架另通过 C# 30 项本地检查及 76 项 PostgreSQL HTTP 检查、Rust 五项测试及 77 项 PostgreSQL HTTP 检查，格式／Clippy 检查通过。首轮曾发现限流 SQL 参数类型推断与并发回执事务冲突，修复后完整重跑通过；保留首次失败日志，未用后续成功覆盖原始失败。

生产仍需部署共享私有配置、受限数据库身份、维护清理和 worker 启停，并按目标服务器与恢复方案验收。产品的后续签名计划及 SQLite 文件 worker 适配见其各自文档，产品数据库迁移仍是独立工作。

## SQLite 同机任务适配

`SqliteTaskQueue` 为现有同步 `SqliteStore` 提供相同任务状态、不可变幂等载荷、数据库时钟、代次／token 租约、心跳、有限重试、TTL、外部结果不明隔离、带审计核销及命名空间绑定的游标分页。SQLite 增量迁移 8 只追加 `task_jobs` 与 `task_job_reviews`，不修改迁移 1–7 或 PostgreSQL 的迁移及摘要。业务记录和入队、任务完成和业务结果可用宿主 SQLite 事务原子提交。

这是同一主机上共享私有数据库的多进程队列；不应把 SQLite 文件放到网络文件系统代替 PostgreSQL 多节点方案。准备阶段的租约到期可接管；外部发送阶段到期仍进入 uncertain，不自动重发。任务与幂等元数据不会自动清理，恢复旧备份时宿主仍须先暂停并核对未完成任务。

新增五项默认检查覆盖旧业务数据及重复打开、事务回滚、旧代次、发送不明、核销审计回滚、退避／TTL／分页，以及两个独立 Node 进程竞争十二个任务。框架与产品 vendor 各 96 项默认检查通过。产品个人 EXE 已用此适配器完成本地任务恢复与文件发布验证，未切换产品数据库或调用真实 KOOK／支付平台。
