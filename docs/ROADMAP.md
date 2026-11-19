# 当前能力与后续验收

核对日期：2026-11-19。本文描述已合入 main 的源码 0.7.0，不表示已创建版本标签、发布 npm 包或完成生产部署。SQLite 当前迁移为 8；PostgreSQL 使用独立迁移 1–6、共 41 表。当前能力与外部验收边界见 [演进计划](ROADMAP.md)。

## 已实现的通用能力

| 模块 | 当前实现 | 详细说明 |
| --- | --- | --- |
| 授权核心 | 账号、永久版本及渠道权益、订单快照、异常到账、自然月换绑、额度、短期签名许可证、不可变分发 | [业务契约](CONTRACTS.md) |
| 存储与查询 | 同步 SQLite、AsyncFramework／PostgresStore、订单／分发／审计游标分页 | [PostgreSQL](POSTGRESQL.md) |
| 任务与通知 | 精确事件资源、SQLite 同机任务、PostgreSQL 多节点预算与租约、退避及结果不明核销 | [协调](COORDINATION.md) |
| 浏览器门户 | OAuth state、MFA／恢复码、普通及管理 Cookie、具名权限、明确两步换绑 | [门户](PORTAL.md) |
| KOOK 私信 | 原卡片归属验证、一次性按钮、身份绑定注册交接、通知归属与核销 | [Bot](BOT.md) |
| 原生 SDK | C#／Rust、Ed25519／RSA-PSS、Windows DPAPI 与 HWID 范围、回环 HTTP 验证 | [SDK](../clients/README.md) |
| 签名及恢复 | 手动轮换、PostgreSQL 共享策略／节点就绪／指定计划、认证加密备份与空 schema 恢复 | [签名计划](POSTGRES-SIGNING.md) |
| 离线兼容导入 | 通用 SQLite v6/v7/v8 的审核、锁源封存、整批导入和中断核查 | [迁移](SQLITE-POSTGRES.md) |

这些能力需要按文档显式配置；不会自动将同步产品切换到 PostgreSQL，也不会自动启动真实消息、支付或换钥。EXAMBIA 的身份组政策、见证恢复、TPM、个人 EXE、WPF 更新和优化器仍属于产品层。

## 当前证据

上述实现已通过 [PR #19](https://github.com/MantraChen/product-license-kit/pull/19) 合入 main。2026-11-19 默认检查 103 项、隔离 PostgreSQL 18.7 检查 109 项、demo 与 140 文件公开源码审查通过。2026-11-18 原生 SDK 证据为 C# 30 项本地／76 项 PostgreSQL HTTP，Rust 5 项测试／77 项 HTTP；不能把既往数量写成文档修改后的新测试。

GitHub Actions Windows／Ubuntu 作业因账号计费锁定未启动；维护者普通合并没有修改保护规则，也不等于远端通过。早期阶段数量、迁移及发布事实保留在 CHANGELOG 与专题的带日期记录中。

## 尚未关闭的外部条件

- 真实 KOOK OAuth 应用资格、回调配置、准入身份组、手机私信及生产渠道验收。
- 商户回调验签、主动查单、退款与对账；人工核款记录不等于支付 API。
- 产品文件格式、平台正式签名、私有存储交付与目标代理链验证。
- 目标节点共享配置、数据库权限、故障恢复、生产切库和真实客户端公钥信任过渡。
- 非本机 Windows x64 的原生 SDK 覆盖、TPM 或其他可信硬件适配。
- 运营方选择的独立监测、告警接收和备份保留策略；库不会自动部署这些设施。

## 版本与变更原则

源码仍为 0.7.0，未创建对应发布标签或 npm 包；集成提交、API 版本、schema、产品收费版和客户端构建号分别管理。后续扩展先明确接口、事务和外部结果不明的处理，再实现适配器。产品规则保持在宿主配置及适配层。
