# 文档导航与维护分工

更新日期：2026-11-16。README 是入口；本导航列出全部受版本管理的 Markdown 文档及分工。详细技术说明必须写明读者、前置身份、输入、状态、错误、重试/回滚和验证方式；不能用“已完成”替代验收证据。

## 阅读层级

1. README → [详细契约](CONTRACTS.md)：先确认框架与宿主职责。
2. [API](API.md)、[协议](PROTOCOL.md)、[接入](INTEGRATION.md) 分别负责字段、签名与外部适配。
3. [运维](OPERATIONS.md) 与 [治理](REPOSITORY.md) 负责升级恢复、验证与发布。

## 全部文档清单

| 文档 | 层级与维护范围 |
| --- | --- |
| [.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [CHANGELOG.md](../CHANGELOG.md) | 历史与变更证据；保留日期，不当作当前操作说明 |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | 许可、贡献或安全政策；不因产品状态变化改写法律条款 |
| [CONTRIBUTOR_AGREEMENT.md](../CONTRIBUTOR_AGREEMENT.md) | 许可、贡献或安全政策；不因产品状态变化改写法律条款 |
| [README.md](../README.md) | 入口与文档分工，不重复完整接口表 |
| [clients/README.md](../clients/README.md) | C#／Rust SDK、Windows 密钥与 HWID、跨语言验收和工具链 |
| [SECURITY.md](../SECURITY.md) | 许可、贡献或安全政策；不因产品状态变化改写法律条款 |
| [docs/API.md](API.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/ARCHITECTURE.md](ARCHITECTURE.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/COORDINATION.md](COORDINATION.md) | PostgreSQL 共享限流、持久任务租约、通知 worker 与结果不明核销 |
| [docs/BOT.md](BOT.md) | KOOK 私信菜单、购买按钮验证、一次性网页注册、通知与投递核对 |
| [docs/POSTGRES-SIGNING.md](POSTGRES-SIGNING.md) | 共享签名策略、节点就绪、自动计划、加密备份及空 schema 恢复 |
| [docs/CONTRACTS.md](CONTRACTS.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/INTEGRATION.md](INTEGRATION.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/OPERATIONS.md](OPERATIONS.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/PROTOCOL.md](PROTOCOL.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/POSTGRESQL.md](POSTGRESQL.md) | 异步仓储、PostgreSQL 事务与迁移、隔离验收及业务接线边界 |
| [docs/README.md](README.md) | 入口与文档分工，不重复完整接口表 |
| [docs/REPOSITORY.md](REPOSITORY.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/ROADMAP.md](ROADMAP.md) | 当前技术专题；结合详细契约核对输入、状态、失败和验证 |
| [docs/SYSTEM-GUIDE.md](SYSTEM-GUIDE.md) | 综合手册唯一内容源；修改后同步生成 Word 并校验 |

## 同步与变更规则

SYSTEM-GUIDE.md 是综合手册的唯一内容源，对应 SYSTEM-GUIDE.docx 由 scripts/export-guide.py 生成。摘要与正文检查通过只证明两者同步，排版需单独渲染检查。源码发生路由、状态或安全行为变化时，同时更新字段文档、详细契约和所属功能专题；历史报告只增补澄清，不回写旧测试数量。

本轮不改业务配置、权限、订单、密钥或客户端发布号。开发测试、源码合并、制品发布、生产启用和实机验收必须分别记录。

SQLite v6/v7/v8 离线兼容迁移入口、停机保护及中断核查见 [迁移说明](SQLITE-POSTGRES.md)。产品及 V5 数据不在此导入范围。

[PORTAL.md](PORTAL.md) 说明可复用浏览器门户、具名权限、MFA、Cookie 与恢复边界。

[BOT.md](BOT.md) 说明可复用私信交互；真实 OAuth 和平台消息验收保持独立。

主手册 SYSTEM-GUIDE.md／Word 目前保留 2026-11-16、0fa8044 源码基线的同步版本；本工作树后续 PostgreSQL、分页、多节点、SDK 和门户能力以对应专题为准。更新主手册的视觉验收受当前 Windows 打包渲染器缺少 LibreOffice 阻碍，尚未据内容提取或旧预览宣称新版排版通过。
