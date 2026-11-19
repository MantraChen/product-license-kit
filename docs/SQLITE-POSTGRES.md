# SQLite v6/v7/v8 到 PostgreSQL 的离线兼容迁移

核对日期：2026-11-19。本文描述已合入 main 的源码 0.7.0，不表示已创建版本标签、发布 npm 包或完成生产部署。SQLite 当前迁移为 8；PostgreSQL 使用独立迁移 1–6、共 41 表。当前能力与外部验收边界见 [演进计划](ROADMAP.md)。

此工具只导入通用框架表，不导入产品 exa_ 表或 V5 旧数据；切库和恢复必须独占写入者，不能边运行产品边迁移。

工作区提供 `inspectSqliteMigration`、`migrateSqliteToPostgres`、`reviewSqliteCutover`，以及 `examples/sqlite-postgres.mjs` 操作入口。只支持本框架已知的 SQLite v6/v7/v8 精确布局；不是 EXAMBIA 产品或 V5 数据导入器。附加业务表、视图、触发器、改动的列／约束／索引、未知版本均拒绝（三个已知只读游标索引允许缺失，存在时仍须匹配），不能静默遗漏宿主数据。

本地实现完成，不代表已切换产品生产库。产品继续运行 SQLite。源服务、目标 API/Bot/worker 必须由操作员先停止，旧版程序不得在切换后重新启动；不要通过硬链接、另一份数据库副本或绕过适配器访问同一个部署。

## 保留与暂停

迁移保留账号 ID、平台身份、付款与异常流水、订单历史快照、权益及来源／渠道、设备 ID／公钥／指纹、绑定代次、冷却、重置记录、精确整数额度、命令幂等结果和审计。分发清单按显式历史公钥验签，并核对 ID、版本、哈希并校验签发时刻；历史签发时间与完成落库时间分别保留，不要求毫秒相同；已签字符串保持原样。当前服务签名私钥不轮换，目标运行配置必须使用同一 issuer、目录和信任材料。已停用的权益版本或绑定组在目录中缺失时要求先审核目录。

会话、邀请、挑战不导入，用户须重新登录。pending／leased／sending 任务变为 uncertain，清除旧租约并递增 generation，结果须核销后才能重试；已结束任务和历史核销记录保留。旧 outbox 及精确资源关联原样保留，**不从历史通知创建新投递任务**。v6/v7 源无任务表，v6 源另无通知资源关联表且不猜测历史关联，迁移时对应目标表为空。

## 预检

先构建框架并由单独的数据库维护身份初始化目标 schema 到当前版本，再关闭初始化连接。迁移 4 只追加 `compatibility_imports`，后续迁移 5 另追加门户七表，当前共 35 表；迁移 1–4 的 SQL 和 SHA256 不变。导入要求所有框架数据表均为空，不能覆盖、合并或重复追加。

私有 JSON 配置示例，所有相对文件路径按配置文件目录解析；不要提交此文件：

```json
{
  "database": "source/framework.sqlite",
  "issuer": "your-existing-issuer",
  "catalogFile": "catalog.json",
  "signingKeyFile": "source/signing.pem",
  "historicalPublicKeyFiles": [],
  "backupDirectory": "private-backups",
  "backupPasswordFile": "backup-password.txt",
  "actor": "operator-name",
  "reason": "approved offline framework cutover",
  "postgres": {
    "connectionString": "postgresql://migration_user:PRIVATE_PASSWORD@db.example/framework",
    "schema": "plk",
    "caFile": "postgres-ca.pem"
  }
}
```

远端 PostgreSQL 必须验证 CA 与主机名；本机回环可不设 caFile。备份密码文件为 20–256 字符口令，入口移除末尾换行；不要在命令参数中放密码。工具保护配置、私钥与口令文件权限，不导入 `.env`，不自动查找实际部署或修改连接串。

```powershell
$env:PLK_SQLITE_MIGRATION_CONFIG_FILE = '你的私有迁移配置绝对路径'
pnpm build
node examples/sqlite-postgres.mjs --review
# 审核 counts、clearedAuthenticationRows、pausedTasks、heldNotifications 和 planHash。
# 停止所有源与目标进程后，明确使用刚刚审核的摘要：
node examples/sqlite-postgres.mjs --apply <planHash>
```

review 只对读取快照进行校验，不运行源迁移或返回用户数据。包含已提交 WAL；最多 250,000 行、256 MiB 原始快照／逻辑内容，超限拒绝。私有临时目录仅存本次快照和布局参考，结束后验证路径再清理。审核摘要绑定源逻辑数据、版本、issuer、完整目录、当前／历史公钥及目标迁移摘要；源或配置变化必须重新审核。apply 不接受过期摘要。

## 切换保护

apply 持有源 `framework.lock` 和 SQLite `BEGIN IMMEDIATE` 写入保留锁，整个异步导入期间阻止直接 SQLite 写入，最后回滚该空事务，不改源业务行。PostgresStore 的每个普通物理连接持有 schema 级共享会话 advisory lock；维护模式只有一个不闲置回收的物理连接，取得同一键的独占会话锁。任一运行连接、其他维护进程或新启动运行进程冲突即拒绝。维护连接丢失后不自动重新取得持有资格。独立 SQL 客户端和旧二进制不遵守此协议，部署必须禁用其写入权限；此方案不支持事务池模式的代理。

先在新文件创建并验证 AES-GCM 加密备份，内容为完整 SQLite 快照、当前私钥、迁移目录／公开信任及审核计划。备份和首次源切换标记写入时请求文件 flush；只有读取、解密并逐项核对通过才继续。备份口令不进入报告；成功返回加密包路径及 SHA256。配置凭据、部署文件、制品文件须按宿主既有方案保存，本工具不复制它们或上传异地。

目标先持久记录 pending，再独占创建源 `<数据库路径>.postgres-cutover.json`。源 SqliteStore 看到 pending 或 completed 标记均拒绝启动。随后整批业务导入、迁移审计及目标 completed 同事务提交；新连接和运行连接重建均检查目标 pending，存在则拒绝服务。不会自动重试任何导入事务或删除切换标记。

## 中断与核查

不要仅凭命令报错就删除标记、重跑 apply 或改回旧连接串。维护身份连接目标，使用同一私有配置执行：

```powershell
node examples/sqlite-postgres.mjs --status
```

status 重新验证源逻辑摘要、issuer／目录／信任上下文，以及目标记录和完成审计；只读，不启动服务、不更新标记。`committed:true` 表示目标已有原子完成记录；源标记仍为 pending 可能只是提交回执或最后文件更新丢失。完成后应在隔离目标验证重新登录、原设备证明、权益、分发和任务核销，再由操作员切换配置启用目标，源继续封存。

`targetStatus:pending` 表示导入未确认完成，目标运行被阻止。SQL 导入失败时业务行整体回滚，但 pending 和备份保留；不要自动解除封存。若中断发生在创建源标记之前，status 无文件可读，维护身份应检查 `compatibility_imports` 中的 pending 记录、加密备份与源状态。须在确认目标从未接收新业务、备份可恢复且所有进程停止后，制定单独恢复步骤。已在 PostgreSQL 接收新付款／绑定后，不能通过开启原 SQLite 进行回退。

## 本地验证

`pnpm test:postgres` 的真实 PostgreSQL 临时集群覆盖 v6/v7/v8 迁移、已付权益、接近安全整数上限的额度、原设备证明签发、旧分发清单不变、租约隔离、停机锁、直接 SQLite 写入竞争、连接丢失及重建、摘要变化、未知产品表／版本／列、签名篡改、空目标约束、整批回滚和提交回执丢失核查。全部仅使用合成数据，未导入产品实际 `.data`，未执行生产切库。

依据：[SQLite VACUUM INTO 一致快照](https://www.sqlite.org/lang_vacuum.html)、[PostgreSQL 会话 advisory locks](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS)。

2026-11-18 最终：框架与产品 vendor 各通过 76 项 PostgreSQL 检查、96 项默认回归；产品生产构建及 481 项测试通过。C# 30 项本地／76 项 PostgreSQL HTTP 检查、Rust 五项测试／77 项 PostgreSQL HTTP 检查通过；其后新增 v6 用例及修正历史时间校验，再由两处 76 项 PostgreSQL 全量确认。125 个公开源码文件哈希一致；正式 EXE 签名、实际 OAuth 和生产迁移未执行。
