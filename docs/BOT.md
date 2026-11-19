# KOOK 私信交互适配器

核对日期：2026-11-19。本文描述已合入 main 的源码 0.7.0，不表示已创建版本标签、发布 npm 包或完成生产部署。SQLite 当前迁移为 8；PostgreSQL 使用独立迁移 1–6、共 41 表。当前能力与外部验收边界见 [演进计划](ROADMAP.md)。

真实 OAuth、手机私信及通知接收目标仍需目标配置；本地模拟消息不算实传。通用 Bot 不自动采用产品工单、见证恢复或个人收款码政策。

面向框架宿主与维护者。2026-11-18 的未提交工作树实现 `PostgresKookBot`、`KookBotClient`、`KookWebhookDecoder`、`createKookBotApp`，需要 PostgreSQL 迁移 6，以及同一个 `AsyncFramework`／`PostgresPortal` 实例。它不替产品写入 KOOK 身份组、设备恢复政策或支付到账记录。

## 接收与验证

独立 HTTP 服务只有 `GET /health` 和 `POST /webhook`。接收原始字节，按私有配置处理默认 zlib deflate 或 `compress=0`，核对 `verify_token`；配置 Encrypt Key 后必须使用双 Base64、AES-256-CBC、PKCS#7 的加密信封，不能降级为明文。该机制是共享令牌和传输加密，不称为平台数字签名。原始与解压后的请求分别最多 1 MiB，平台 REST 响应最多 128 KiB。

Challenge 直接返回 `{challenge}`。有效私信先提交数据库任务再回 HTTP 200，回调中不查询 KOOK、不发消息、不创建订单。平台要求一秒内回执；部署需控制代理并发、数据库延迟并监控回执时间，代码不能保证任意负载下的一秒时限。数据库提交回执不明时返回失败，平台重投由持久任务核对。

仅接收 PERSON 的 `/menu`／`菜单`、`/buy`／`购买`、`/account`／`我的账号`、`/register`／`注册`，以及 `message_btn_click`。群组事件和 Bot 作者被忽略；界面采用独立私信卡片与网页入口。用户 ID 全程作为数字字符串保留，手机端长私信目标不参与账号推断。事件时间最多落后数据库五分钟、超前三十秒；以 epoch 与事件 msg_id 去重，同 ID 的不同有效载荷拒绝。sn 回绕不会合并不同事件。

## Worker 与业务状态

`runInbox(limit)`、`runDeliveries(limit)`、`runNotifications(limit)` 的 limit 为 1–100。每次调用顺序处理，宿主可运行多个节点；共享任务租约默认九十秒、三十秒续租，以 token／generation 验证所有写入。平台调用和宿主准入函数每次最多等待八秒；超时不取消已经可能发生的外部发送，所以该发送进入结果不明状态。

宿主必须提供实时准入函数及 `admissionVersion`；参考部署按指定 KOOK 服务器的任一许可身份组准入，没有内置产品身份组。处理交互和投递时分别重新检查；OAuth 注册完成时门户再次检查。外部资格不能与本地数据库原子提交，权限变化后必须依赖下一次查询，不能宣传为跨平台强事务。

| 操作 | 验证与结果 |
| --- | --- |
| 菜单／账号 | 查询此 KOOK 身份对应的账号，拒绝停用账号，提供用户中心入口 |
| 购买页 | 每页十二个报价，支持前后页；显示整数最小货币单位，不用浮点换算 |
| 购买按钮 | 不透明随机 nonce，绑定收件人、原消息、过期时间与报价摘要；核对官方私信会话的对端、原卡片作者、消息类型及完整内容摘要 |
| 创建订单 | 当前账号与报价资格重新核对，报价变化要求重开入口；同按钮只能消费一次。订单、按钮结果、后续卡片计划和收件任务完成在同一事务提交 |
| 注册 | 只生成此 KOOK 身份可用的五分钟一次性网页交接，不创建原生 invitation，不下发 native bearer，不自动发放权益 |
| 通知 | 显式启用后复用 outbox／`PostgresNotificationWorker`，消息携带事件及准确业务资源 ID；同 issuer 只允许一个适配器命名空间拥有通知队列 |

购买只产生待付款订单。个人收款码场景仍由操作员核对到账；这里没有新增商户凭据、自动到账确认、退款或对账能力。

按钮与交接令牌有效五分钟。重复按钮复用原结果，不再发一条重复消息。原消息尚未记录平台回执时，按钮任务安全等待重试；平台作者、对端或内容核对失败时不执行业务。已发送卡片必须保持原内容，宿主修改卡片会导致其按钮验证失败。

## 注册进入门户

私信链接为 `https://门户/#register=<随机令牌>`。浏览器立即清除地址片段，只保留内存；明确勾选注册确认后，令牌通过同源 JSON POST `/api/auth/start` 的可选 `registration` 字段传入。已有会话时界面明确说明并先退出该会话。刷新确认页后需要重新打开私信链接。

`registrationAdmission` 缺省时门户禁止注册交接，普通已注册账号登录照常。启用后，门户先消费绑定浏览器的 OAuth state，再到平台验证授权码；最终事务锁定交接，验证 provider／subject、期限、撤销、消费状态及 Bot 当前 epoch／暂停状态，同时创建唯一账号、审计、注册 outbox、消费交接和待 MFA 会话。错误身份不会消费交接，OAuth state 本身已用完。并发流程只有一个能注册；提交结果不明时不可重复换码，应重新普通登录核对。

`AsyncFramework.registerVerifiedIdentity` 仅供已验证身份的可信宿主在事务内接线，不是公共 HTTP 路由；不能直接暴露一个接受 provider／subject 的注册接口。首次注册仍需设置并验证 MFA 才能使用门户业务。详见 [门户契约](PORTAL.md)。

## 私有参考配置

`examples/portal-server.mjs`／`pnpm start:portal` 的私有 JSON 可增加以下可选对象。实际 Bot token、Verify Token、Encrypt Key 分别由私有文件读取，不能提交仓库；OAuth Client ID／Secret 仍按门户配置。尚未开通 OAuth 资格时只做合成平台验证。

```json
{
  "kookBot": {
    "namespace": "licensed-users",
    "botId": "900001",
    "tokenFile": "private/bot-token.txt",
    "verifyTokenFile": "private/webhook-verify.txt",
    "encryptionKeyFile": "private/webhook-encrypt.txt",
    "compressed": true,
    "guildId": "800001",
    "anyRoleIds": [7, 8],
    "admissionVersion": "reviewed-policy-1",
    "host": "127.0.0.1",
    "port": 3201,
    "workerEnabled": false,
    "sendEnabled": false,
    "notificationsEnabled": false
  }
}
```

示例均为占位值。默认三项开关全关，启动不会发送消息；开启 worker 时先查询 `user/me` 验证 token 对应配置的 Bot。通知与交互投递需分别显式启用；反向代理仅公开 webhook，原生管理令牌不能用于这个入口。日志不输出 webhook 原文、授权码、注册令牌或凭据。

KOOK Webhook 与 WebSocket 不能同时接收同一应用事件，且每个应用只有一个回调 URL。此通用适配器采用 Webhook；产品现有 WebSocket Bot 保持其部署选择，不能直接把这个端口开启当成产品线上迁移。启用前应确定应用与回调路由归属。依据 [KOOK Webhook 官方说明](https://developer.kookapp.cn/doc/webhook)、[按钮事件](https://developer.kookapp.cn/doc/event/user)、[私信接口](https://developer.kookapp.cn/doc/http/direct-message)及[私信会话接口](https://developer.kookapp.cn/doc/http/user-chat)。

## 失败、核对与恢复

发送前持久记录 `sending`，成功后在同一事务记录平台消息 ID／会话和完成任务。明确平台拒绝可退回 pending，按有界退避重试；超时、5xx、成功响应不可解析、提交回执不明或 sending 租约失效进入 uncertain，不自动重发。`nonce` 不当作 KOOK 的幂等发送保证。

可信操作员可调用 `resolveDelivery(key, input)`。`published` 必须提供平台 messageId，适配器主动查验作者、对端和卡片摘要；`retry` 必须明确 `confirmedNotSent:true`，不能把“没查到”当作证据；还可取消。输入包括当前 generation、具名 actor 和 3–500 字原因，由任务 review 表持久记录。同样保留通知 worker 的人工核对接口，不自动核销历史失败任务。

`review({paused,epoch,actor,reason})` 用于具名暂停／恢复；暂停递增 epoch，使旧按钮和交接失效。暂停不能撤回已经开始的网络发送。配置 Bot ID、私有凭据摘要、准入版本、Webhook 模式或门户上下文不匹配会拒绝启动／运行，需维护者审查配置，不清空设置绕过检查。

卡片内容（包括注册链接）使用从门户根密钥按命名空间派生的 AES-GCM 子钥加密存储；任务只保存消息 ID 或已散列的按钮值。备份必须包含已有门户根密钥，不能额外猜测新 Bot 密钥。恢复保留历史消息与任务凭据，将 Bot 设置暂停并递增 epoch，撤销所有旧交接、清空按钮及注册 OAuth 关联；未完成任务按原协调协议进入 uncertain。具名恢复后仍不能投递旧 epoch 的卡片，需核对或取消，再创建新交互。

本地测试包含合成 KOOK REST、真实 PostgreSQL 并发、事务回滚／提交回执不明、OAuth 交接与 MFA、发送待核对、通知唯一归属以及加密恢复。它们不证明真实应用已开通 OAuth、真实手机已收卡片或个人收款自动查单可用。

2026-11-18 本阶段最终验证：框架及 vendor 各 100 项 PostgreSQL 18.7 检查（新增十三项 Bot 集成）、103 项默认回归（新增六项协议／REST 检查）通过；C# 30 项本地／76 项 PostgreSQL HTTP 检查、Rust 五项测试／77 项 HTTP 检查通过。产品生产构建及 481 项全量测试通过。140 个公开框架文件与 vendor 哈希一致，冻结 TPM 快照 552 文件无变更。独立浏览器验证确认勾选、移除 URL 片段、OAuth、MFA 和刷新登录，合成账本最终为一账号、一份 MFA、零付费权益。

通知入口固定按 `providers:['kook']` 领取，混合身份库中的其他平台任务保留给对应消费者；独立消费者须使用明确的平台名单，或者由宿主使用可识别全部平台的统一路由 sink。发送准备及 KOOK 准入检查后均核对宿主账号状态，宿主 `accountEnabled` 策略不被绕过。身份在准备期间变化时归还尚未发送的租约，旧收件人不会被用于该次发送；已发送结果不明的任务保持人工核对。默认所有实际发送保持关闭，详细路由契约见 [多节点协调](COORDINATION.md#通知接线与核销)。

随后通知路由修复阶段，框架及 vendor 各通过 109 项 PostgreSQL 检查、103 项默认回归；产品生产构建及 481 项测试通过。新增九项真实数据库检查覆盖任务白名单、交接与旧 token、两个独立进程各投递五条不同平台通知、准备期间身份变化、结果不明不改路重放、账号表只读权限、KOOK 与其他平台并存、宿主停用及准入期间停用。初始复现证明其他平台任务曾产生一次无效失败，修复后保持未领取，尝试次数为零；全部发送均在隔离本地替身中完成。
