# 接口、状态与异常处理补充

文档核对日期：2026-11-16；适用于源码 0.7.0，不表示已发布 npm 包。本说明面向宿主服务开发者，规定跨接口的状态与重试边界；逐路由字段见 API.md，密码或支付凭据不属于协议示例。

## 1. 角色、输入与权限

HTTP 用户接口使用普通 Bearer 会话；管理员使用独立管理令牌。用户身份不等于管理员权限，管理员令牌也不能冒充用户会话。浏览器门户必须通过同源后端隔离管理令牌；可选的 PostgresPortal／createPortalApp 已提供通用 Cookie、MFA 与具名权限。PostgresKookBot 提供私信按钮与原卡片归属校验，产品身份组政策由宿主配置，见 [Bot 契约](BOT.md)。

JSON 请求上限 16 KiB，路由采用严格字段校验。400 先检查输入，401 核实当前认证材料，403 检查账号状态和权限，409 重新读取业务状态，429 退避。相同 Idempotency-Key、操作、账号和载荷重放原结果，同键不同载荷拒绝；响应丢失不能换新键盲目再做一次扣费操作。

## 2. 订单与付款

创建订单读取商品、当前权益和来源渠道，保存报价快照；后续调价不改旧快照。edition/upgrade/channel/rebind 决定发放对象，不能由客户端任意提交目标权益。Beta 商品还需复核来源渠道；付款确认再次核实资格。

订单区分 pending、paid、cancelled；到期还由 order_deadlines 的 expires_at 判断。超期不意味着实际收款不存在。取消不能伪装成退款，异常到账必须显式记录和复核，过期核款需理由。付款流水、发放、审计和 outbox 在业务事务中处理，重复已确认流水不得产生第二次权益。

外部支付验签、商户查单、退款与账单对账由宿主适配器实现；HTTP 响应成功不替代银行或平台到账证据。异常款的退款登记也不代表框架调用了商户退款 API。

## 3. 设备与自助重置

GET /v1/devices/:groupId/reset 返回 state、generation、freeAt、credits、cost、canReset。state 为 unbound、bound、reset-pending；预览不扣额度。POST 同路径需用户认证、Idempotency-Key，输入 generation、cost:free|credit、confirm:true。

提交时再次检查拥有该组权益、绑定代次及当前费用。DEVICE_BINDING_CHANGED 要刷新绑定，DEVICE_RESET_COST_CHANGED 要重新展示费用并确认，REBIND_COOLDOWN 不能绕过。成功重置使绑定 disabled、代次增加，建立待绑定机会；免费成熟资格优先，否则消耗一份额度，并按目录自然月规则确定新 freeAt。

随后首次成功激活消费 pending reset，不再扣一次额度，也不重新延长刚确定的冷却。设备原公钥与指纹一致时按 same-device 处理；其他替换按目录换绑规则执行。指纹是客户端输入，不是硬件证明；原机重装恢复若免除正常换绑，宿主必须自行承担证据与防滥用设计，不能宣称框架已有 TPM 原机认证。

## 4. 挑战与许可证

注册设备及签发许可证都要签署服务器发出的准确挑战。scope 由账号、组或设备、代次、版本和渠道决定。过期、已使用、错误签名或状态变化的挑战不能复用；先重新申请挑战，再签名，不对失败的消费请求自动无限重放。

设备公钥只接受 Ed25519 或 RSA-2048/PSS-SHA256 的规范 SPKI；RSA 指数为 65537，盐长度为 32 字节，算法由保存的公钥决定，不能用请求参数切换弱算法。服务端信封仍使用 Ed25519，必须区分 license、distribution、operation 与取消回执的类型。

客户端固定可信公钥并检查 issuer、账号、设备、版本、渠道、硬件摘要、generation 和时效。/v1/signing-key 是公钥查询，不是安全的首次信任建立。停用、身份关联变化和设备撤销阻止后续签发，但已签发离线令牌仍可能存活至其到期；宿主若需要执行前在线撤销检查，必须实现自己的在线消费入口。

## 5. 分发、通知与迁移

reserve → finalizeDistribution 的分发流程分别确定归属与最终文件哈希。finalize 后不可换内容；同一分发提交不同哈希拒绝。签名清单不包含可公开泄露的管理员或客户认证秘密。示例 JavaScript 分发不是 Windows EXE 工厂或 Authenticode。

业务事务将事件写入 outbox。同步 Framework 由宿主通过单个 worker 调用 `framework.dispatchNotifications(sink)`，失败保留待投递记录和尝试次数。AsyncFramework 的新事件另在原业务事务中创建 PostgreSQL 通知任务，使用多进程租约、心跳、退避及 generation；发送结果不明进入核销，不自动重发。核销、审计与确认回执同时提交，宿主负责验证操作员和平台证据。详见 [多节点协调](COORDINATION.md)。旧 outbox 不自动补任务，重发历史事件前核对主题与业务结果，避免重复通知已经完成的业务。

工作区迁移 7 新增 `outbox_resources`，与原事件在同一业务事务中写入资源类型和 ID。付款事件关联实际订单，分发事件关联实际分发，权益事件关联版本，设备事件关联实际设备；其余框架事件关联账号。`Notification.resource` 是可选字段，旧事件不补猜订单关系。消费器应按资源 ID 重新核对归属和当前状态，不能把资源引用当作身份凭据。投递批量限制为 1–100，默认 20；该方法仍不提供网络平台的恰好一次保证或多 worker 租约。

当前使用同步 SQLite 与事务；迁移版本由 plk_migrations 管理。升级前一致性备份，恢复到新目录检查完整性、权益、付款及绑定。不支持把运行中的单个数据库主文件直接当作一致性快照。文件密钥、数据库和恢复口令分别保护；框架不能自动提供 PostgreSQL、多节点任务租约或分布式限流。

## 6. 检查证据与职责边界

运行 pnpm check、pnpm demo、pnpm audit:source 和生产依赖审计；文档 Markdown/Word 同步检查不替代视觉渲染。远端 CI 未启动、被计费阻止或网络失败应分别记录，不记为测试通过。提交源码和文档不等于部署宿主或发布 npm 版本。

可选通用用户门户和 MFA 见 PORTAL.md，KOOK 私信交互见 BOT.md；其他 Bot 平台、支付商户、硬件采集、TPM 证明、Windows 执行、对象存储和安装包分发仍属于相应适配器／宿主接入，不因某产品实现而变成授权核心内置。API.md、PROTOCOL.md 与 INTEGRATION.md 分别拥有字段、签名和适配边界的解释权。
