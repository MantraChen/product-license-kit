# HTTP API v1

文档分工核对：2026-11-19。本页负责HTTP 字段、认证与响应；跨步骤状态与异常处理见 [详细契约](CONTRACTS.md#1-角色输入与权限)。适用于源码 0.7.0；历史迁移编号与发布事实按原日期保留。

## 0.7.0 商品兼容说明

目录 `offers.kind` 支持 edition、upgrade、channel、rebind；`channel` 与 `requiresChannel` 的可选值为 beta。HTTP 路由保持不变，新增商品仍走原下单和核款接口。库方法 `bestUpgradeOffer` 新增可选第三参数 stable/beta，默认 stable。具体资格与付款来源规则见 [接入指南](INTEGRATION.md)。


默认本地地址 `http://127.0.0.1:3100`。生产必须通过 HTTPS。JSON 请求体上限 16 KiB。响应禁止缓存。通用错误：`{"error":"CODE"}`；400 为输入错误，401 为认证失败，403 为权限不足，409 为状态冲突，429 为限流。

本接口供客户端和服务端调用。不接受带 Origin 的浏览器请求，不使用 Cookie，也不开放跨域。门户应通过自己的同源后端接入，不要把管理员凭据传给浏览器。

`createApp` 同时接收同步 Framework 和异步 AsyncFramework；响应数据格式一致，身份验证及写入都等待完成。异步仓储不可用返回 503 `STORAGE_UNAVAILABLE`；已回滚且允许重试的冲突带 `retryable:true` 和 `Retry-After:1`。提交／自动提交回执不明分别返回 `TRANSACTION_COMMIT_UNCERTAIN`／`POSTGRES_RESULT_UNCERTAIN`，`retryable:false`，须按业务记录核实结果。详见 [PostgreSQL](POSTGRESQL.md)。

## 认证

普通用户：`Authorization: Bearer <session.accessToken>`。管理员：相同 Header 形式，使用私有 `.env` 中独立生成的 `ADMIN_TOKEN`。管理员令牌不能替代普通用户身份，用户会话也不能访问管理端。

`/auth/register` 与 `/auth/login` 每 IP 每分钟最多 10 次；默认全局每 IP 每分钟 120 次。默认不信任代理传来的 IP Header，生产代理配置见部署说明。

需要幂等的写入必须提供 `Idempotency-Key`：16–128 个英数字、下划线或连字符。相同账号、操作、键和请求会重放原始结果；同键不同请求返回 409。数据库永久保存当前版本的幂等记录；后续清理需要定义重试保留期。支付确认通过订单与支付流水实现幂等。

## 公开与身份接口

| 方法及路径 | 请求 / 结果 |
| --- | --- |
| `GET /health` | 进程健康状态；不是数据库备份/完整服务探针 |
| `GET /v1/catalog` | 产品、版本、设备组、商品配置 |
| `GET /v1/signing-key` | 公共验签密钥与 issuer；首次信任仍须来自安全部署渠道 |
| `POST /v1/auth/register` | `{ticket, proof}` → `{accessToken, accountId, expiresAt}` |
| `POST /v1/auth/login` | `{provider, proof}` → 同上 |
| `POST /v1/auth/logout` | 用户认证；撤销当前会话 |

注册票据由后台发放并绑定外部身份。`proof` 对 KOOK 为 OAuth access token，对本地开发适配器为本地生成的随机凭据。门户可使用 KookOAuthClient，在保存、验证并消费浏览器绑定的 state 后，调用 exchange(code) 取得平台 token，再通过现有 KookIdentityProvider 和框架注册／登录入口核实身份。平台 token 保存在服务端调用链中。需要直接接入宿主认证时可使用 verify(code) 取得已核实身份。authorizationUrl(state) 仅请求 get_user_info，平台请求来源固定，适配按 KOOK 公开的 confidential-client 授权码协议执行。浏览器会话、MFA 和操作员策略由门户管理。参考 [KOOK OAuth](https://developer.kookapp.cn/doc/oauth2) 和 [授权码交换](https://developer.kookapp.cn/doc/http/oauth)。

## 用户接口

库通知接口 `framework.dispatchNotifications(sink, limit = 20)` 接受 1–100 的整数批量。`sink.send(event, identity)` 中，事件为 `{id,topic,accountId,createdAt,resource?}`；新框架事件的 `resource` 为 `{kind,id}`，kind 可为 account、order、entitlement、device、distribution。付款的 order 资源精确引用本次订单，distribution 资源精确引用本次已完成分发。旧库事件缺少资源时继续省略该字段，不按时间、账号最近订单或主题猜测。资源引用不包含下载凭据、支付流水、密钥或签名清单；接收者仍须重新验证资源归属与当前状态。

同步 Framework 继续采用单 worker、至少一次通知语义。AsyncFramework 已接入 PostgreSQL 多进程租约、心跳和退避；普通发送异常进入结果不明核销，仅明确未接收的 NotificationNotSentError 自动退避。详见 [任务与通知协调](COORDINATION.md)。HTTP 共享预算通过 createApp 的 sharedRateLimiter 显式接入，不配置时仍是本机内存限流。

| 方法及路径 | 请求 / 结果 |
| --- | --- |
| `GET /v1/me` | 当前账号、版本权益、设备绑定、额外次数 |
| `GET /v1/orders` | 无查询参数时返回最近 100 条本账号订单；设置 `limit=1..100` 或 `cursor` 时返回 `{items,nextCursor}`，默认每页 30 条 |
| `POST /v1/orders` | `{offerId}`；需要幂等键；返回订单 ID 与价格快照 |
| `POST /v1/orders/:id/cancel` | 仅可取消本账号待支付订单 |
| `POST /v1/devices/challenges` | `{groupId, publicKey, fingerprint:{schema,digest}}`；Ed25519 或 RSA-2048/PSS-SHA256 的规范 SPKI PEM 公钥；digest 为 64 位小写十六进制 |
| `POST /v1/devices/activate` | `{challengeId, signature}`；需要幂等键；返回设备 ID、代次、成本和下次免费时间 |
| `GET /v1/distributions` | 无查询参数时返回最近 100 条本账号已完成且仍有权益的分发清单；设置 `limit=1..100` 或 `cursor` 时返回 `{items,nextCursor}`，默认每页 30 条；不包含下载 URL |

公钥与硬件指纹属于客户端输入。硬件指纹只作为元数据存储，不授权登录或自动恢复。激活必须由用户明确确认替换设备，再提交签名挑战。

订单与分发分页按创建时间、ID 倒序，游标绑定当前账号和列表类型。将响应中的 `nextCursor` 原样传入下一页，返回 null 时结束。翻页期间新建的较新记录留待重新请求第一页。分发在分页前筛选已完成且当前仍有权益的记录，每次翻页重新核对权益与账号状态。`GET /v1/admin/audit` 使用同样的分页参数及响应，继续要求管理员认证。无查询参数的三个入口沿用数组响应。

## 设备认证接口

| 方法及路径 | 请求 / 结果 |
| --- | --- |
| `POST /v1/licenses/challenges` | `{deviceId, editionId}` → `{challengeId,message,expiresAt}` |
| `POST /v1/licenses/issue` | `{challengeId,signature}` → `{token,expiresAt}` |

这里不用用户会话，使用设备挑战签名认证。挑战有效期五分钟、单次使用。网络丢失响应时重新申请挑战，不能重用已消费的挑战。每次签发再次检查设备和权益状态。

## 管理接口

| 方法及路径 | 请求 / 结果 |
| --- | --- |
| `POST /v1/admin/invitations` | `{provider,subject}` → 三十分钟有效的单次注册票据 |
| `GET /v1/admin/accounts/:id` | 账号状态 |
| `POST /v1/admin/accounts/:id/status` | `{active,reason}`；停用撤销会话、挑战与设备刷新，恢复不复活旧令牌 |
| `POST /v1/admin/accounts/:id/identity` | `{provider,subject,reason}`；变更关联身份并撤销旧会话与设备刷新 |
| `POST /v1/admin/accounts/:id/credits` | `{groupId,count,reason}`；需要幂等键；赠送 1–100 次 |
| `POST /v1/admin/accounts/:id/revoke` | `{editionId,reason}`；撤销单个版本权益，不执行退款 |
| `POST /v1/admin/orders/:id/confirm` | `{method,reference,amount,currency}`；method 为 `manual-wechat` / `manual-alipay` / `manual-bank` |
| `POST /v1/admin/distributions` | `{accountId,editionId,releaseId}`；需要幂等键；返回分发编号和可嵌入标记 |
| `POST /v1/admin/distributions/:id/finalize` | `{sha256}`；登记最终文件哈希并取得签名清单，完成后不可修改 |
| `GET /v1/admin/distributions/:id` | 文件归属和发放时身份快照 |
| `GET /v1/admin/audit` | 无参数返回最近 100 条数组；limit/cursor 返回 `{items,nextCursor}`，上限 100 |

本页 /v1 管理 API 是受控后端集成接口，该入口不建立操作员账号或 MFA，核心审计管理员记为 `admin`。可选门户另提供具名权限与 MFA，并记录 portal.admin.* 审计。正式运营应在上层实现有具体身份的授权代理，不让多人共享根密钥。

0.2.0 的 `importEntitlement`、`hasReleaseAccess` 和 `bestUpgradeOffer` 是受控宿主服务方法，没有新增用户自报证据的公开 HTTP 路由。用户 profile 的历史授权 `order_id` 可以为空，并返回按版本保存的 `channels`；消费者不能假设所有权益都来自订单。

完整请求示例见 `examples/demo.mjs`，覆盖真实本地 HTTP 请求和客户端验签。各时间字段除签名许可证的 `iat/nbf/exp` 为 Unix 秒之外，均为 Unix 毫秒。

## 设备自助重置

`GET /v1/devices/:groupId/reset` 需要用户 Bearer 会话，返回 state、generation、freeAt、credits、cost、canReset；预览不扣额度。`POST` 同一路径需要 `{generation, cost, confirm:true}` 和 Idempotency-Key；cost 为 free 或 credit。仅能操作当前登录账号的设备组。状态、代次或费用变化会拒绝确认。

`deviceResetStatus` 与 `resetDevice` 也可由可信宿主直接调用。成功重置停止旧设备续期，作废旧挑战，消费免费机会或一次额度并开始新的自然月冷却。后续一次激活返回 cost=reset，不再扣费、不重新延长冷却。绑定 profile 增加 reset_pending 字段。已签发许可证保持原到期时间，不能远程撤销离线副本。

## 订单有效期

createOrder 返回 expiresAt；orders 返回 expiresAt 与派生状态 expired。默认有效期 24 小时，FrameworkOptions.orderTtlSeconds 可覆盖。cleanupExpired 同时清理过期订单。过期订单确认接口需增加 latePaymentReason（3–500 字符），仅管理 API 可用。手动取消、重复流水、错误金额、失效资格仍拒绝。

## PostgreSQL 签名计划

配置 `createApp(...,{signingCoordinator})` 时增加 `/v1/admin/signing` 的状态、策略初始化、指定公钥计划、带 revision 暂停及恢复核对入口。全部沿用管理员 Bearer 与浏览器 Origin 拒绝策略，不接受私钥或任意文件路径。字段及错误语义见 [签名计划接口](POSTGRES-SIGNING.md#初始化与创建计划)。异步 `/v1/signing-key` 按共享策略返回当前启用公钥；缺钥、未初始化的显式策略或部署摘要不符时为 503。

## 0.5.0 安全与异常到账接口

许可证挑战接受 channel（stable / beta，省略为 stable），签发时再次校验渠道。许可证含 channel、fingerprint；新版 SDK verifyLicense 必须传入本机预期 fingerprint，不能从不可信许可证中抄取预期值。

管理员 GET /v1/admin/payment-exceptions 查询最近记录；POST 同地址提交 orderId、method、reference、amount、currency、reason，登记核实过的实际到账，不授予权益。POST /v1/admin/payment-exceptions/:id/resolve 选择 action=apply 并提交同账号新 orderId 和 reason，或 action=refund 并提交 refundReference 和 reason。refund 仅登记人工已经完成的退款，不调用支付机构。处理及流水占用在同一事务提交，失败回滚，重复处理不重复发放。

## 显式管理版本权限

可信宿主方法 `setEntitlementAccess(accountId, editionId, access, reason, key)`，其中 access 为 `none`、`stable`、`beta`。仅供宿主完成管理员鉴权后调用，没有新增公开 HTTP 端点。方法允许显式恢复撤销权益，保留原订单来源；普通版会清除同版 Beta，撤销会清除所有同版渠道。请求必须包含原因和幂等键，重放旧请求不重新授予权限。平台角色同步属于产品适配器，不在核心中执行。

可选浏览器服务使用独立 `createPortalApp`，同源 Cookie、MFA 和具名权限不改变本页 `/v1` 原生协议。见 [门户接口](PORTAL.md#浏览器接口)。

可选 `createKookBotApp` 仅提供独立 `GET /health` 与 `POST /webhook`，接收原始 KOOK 回调，不接受管理令牌或提交账号 ID 替代平台验证。[Bot 契约](BOT.md) 说明购买、私信按钮、一次性注册与发送结果核对。门户 `/api/auth/start` 可选 `registration` 仅接受此适配器签发的身份绑定交接，最终仍需 OAuth 和 MFA；原 `/v1/auth/register` 不接受该交接令牌。
