# 适配器接入

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
