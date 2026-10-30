# 适配器接入

## 已验证的历史授权（0.2）

宿主必须先从受信平台核实账号身份与购买凭证，再调用 `importEntitlement(accountId, editionId, { source, reference, reason, betaAccess })`。这是宿主服务方法，没有公开认领 HTTP 接口，不能接受客户端自报的身份组。`reference` 使用平台身份与服务器组合的稳定摘要，同一来源、凭证、版本只能属于一个账号。识别已有授权不会覆盖其付款来源，已撤销授权不会自动恢复；重复识别幂等，退群不会撤销已确认的永久权益。

`betaAccess: true` 同时确认本版本普通授权和 beta 资格；普通身份组不会获得 beta。`hasReleaseAccess(accountId, editionId, channel)` 检查账号状态、有效权益及该版本渠道资格。升级后的新版本不继承旧版 beta。产品的文件下载和客户端仍须在交付时调用渠道鉴权。

`bestUpgradeOffer(accountId, targetEditionId)` 按已有有效权益选择最低固定升级价，同价按商品 ID 排序，不会混合比较不同币种。下单与付款确认仍执行原资格检查。

迁移 3 保留已有订单和授权，将 `entitlements.order_id` 改为可空，并增加来源与渠道表。历史认领不生成虚假订单/付款；消费 profile 的产品应兼容空订单号。升级前备份，迁移后回退必须恢复匹配旧代码的备份，不能仅切换二进制。

## 身份与社区平台

实现 `IdentityProvider`，注册到 `FrameworkOptions.providers`：

```ts
interface IdentityProvider {
  readonly name: string;
  verify(proof: string): Promise<{ provider: string; subject: string }>;
}
```

验证必须调用平台、验证平台签名或使用可信认证服务。`subject` 使用稳定 ID，不用昵称。不要实现 `return {subject: proof}` 这样的绕过验证器。

KOOK 适配器使用 Bearer access token 调用官方 `/api/v3/user/me`。设置 `ENABLE_KOOK=true` 启用。当前接收的是已经取得的 OAuth token；浏览器授权、callback 白名单、state、授权码交换需由门户后端完成，`client_secret` 留在服务器。KOOK 的 OAuth 资质需自行申请。Bot 创建邀请的调用应来自受控后端，验证用户事件来源，不能把管理员密钥发给用户。

参考：[KOOK OAuth](https://developer.kookapp.cn/doc/oauth2)、[Token 接口](https://developer.kookapp.cn/doc/http/oauth)。外部集成测试只使用 mock；仓库未对任何真实 KOOK 账号执行注册或发消息。

## 支付

首版支付适配器是人工到账确认。适合没有可靠支付查询/回调接口的起步流程。它不是二维码监听器，也不会读取手机通知自动发货。

正式支付集成需要验证回调签名、商户身份、币种、订单号、金额、实际成功状态和付款流水唯一性，再调用事务化发货用例。必须处理重放、乱序、主动查单和补偿；不要把商户 webhook 直接映射为无认证的人工确认接口。

当前订单属于已注册账号。因此首版推荐先通过社区身份建立账号，再下单。若需要先付款后注册，应新增持久 `purchase_identity` 对象和安全认领流程，不能把待支付订单临时挂在任意第三方账号上。

## 通知

实现 `NotificationSink.send(event, identity)` 后，通过受控 worker 调用 `framework.dispatchNotifications(sink)`。KOOK 示例使用 Bot token 调用官方私信 API；token 不写入源码。只在部署方明确启用 worker 时发送。

首版 dispatcher 为单 worker、至少一次投递。失败事件保留并增加 attempts；未内置定时器、指数退避、死信管理或多 worker 锁。真实服务应按事件 ID 去重并设置退避，避免持续重试故障平台。通知只提醒用户查询受保护的用户中心，不携带可直接激活的永久秘密。

## 用户文件

1. 管理端预留分发编号，确定账号、收费版本和构建版本。
2. 文件处理器从经过审核的发布基线生成带该编号的文件。
3. 执行平台要求的签名和验证，计算最终 SHA-256。
4. 确认分发清单，将文件存入私有对象存储。
5. 下载服务验证用户及当前权益，再返回短时授权 URL。下载权限与客户端运行许可分开验证。

同一账号、同一构建可以复用已生成的文件；更新也必须保留用户标记。原始构建文件不应公开下载。修改格式、移除标记、串通比较和被盗账号都可能影响追溯；不能据此自动归罪用户。

API 当前不接受文件上传、不执行用户命令、不生成下载 URL。演示是可验证的个性化 JavaScript 文件，具体 EXE/MSI/ZIP/PDF 处理和存储由部署方适配。

## 替换数据库

SQLite 使用 WAL、外键和显式写事务，适合单节点。业务服务当前直接使用同步 SQLite 存储接口；PostgreSQL 接入需要引入异步仓储与迁移，保持事务、唯一约束和幂等语义，并运行并发集成测试。不要在网络共享目录放 SQLite，也不要假设多个服务副本的限流与 outbox 已协调。
# 0.1.1 安全集成补充

`FrameworkOptions.accountEnabled(accountId)` 可同步查询产品账号状态，必须显式返回 `true` 才允许；它会在核心授权、设备激活、订单与分发路径中校验，不能只在 HTTP 路由补一处检查。框架内置状态通过 `setAccountActive(id, active, reason)` 更新；停用会撤销会话、挑战与设备，恢复不会复活旧令牌，也不删除永久权益。产品的额外会话应在同一个 `store.transaction` 中撤销，嵌套核心事务由 savepoint 保证整体回滚。

网页接入 `guardBrowserRequest` 时，必须传路由器的匹配路由模板；不要传原始 URL。独立 Bot / 设备路由可以明确列入机器接口，但必须保留它们自己的签名或设备证明。`hashPassword` 使用与 V6 兼容的 scrypt 参数，并限制跨 IP 的并发与排队。
