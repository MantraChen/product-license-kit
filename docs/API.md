# HTTP API v1

默认本地地址 `http://127.0.0.1:3100`。生产必须通过 HTTPS。JSON 请求体上限 16 KiB。响应禁止缓存。通用错误：`{"error":"CODE"}`；400 为输入错误，401 为认证失败，403 为权限不足，409 为状态冲突，429 为限流。

本接口供客户端和服务端调用。不接受带 Origin 的浏览器请求，不使用 Cookie，也不开放跨域。门户应通过自己的同源后端接入，不要把管理员凭据传给浏览器。

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

注册票据由后台发放并绑定外部身份。`proof` 对 KOOK 为 OAuth access token，对本地开发适配器为本地生成的随机凭据。用户 ID 参数不是身份凭据。真实浏览器 OAuth 授权码交换与 state/PKCE 处理由门户适配器实现，未在本服务中内置。

## 用户接口

| 方法及路径 | 请求 / 结果 |
| --- | --- |
| `GET /v1/me` | 当前账号、版本权益、设备绑定、额外次数 |
| `GET /v1/orders` | 最近 100 条本账号订单 |
| `POST /v1/orders` | `{offerId}`；需要幂等键；返回订单 ID 与价格快照 |
| `POST /v1/orders/:id/cancel` | 仅可取消本账号待支付订单 |
| `POST /v1/devices/challenges` | `{groupId, publicKey, fingerprint:{schema,digest}}`；Ed25519 SPKI PEM 公钥；digest 为 64 位小写十六进制 |
| `POST /v1/devices/activate` | `{challengeId, signature}`；需要幂等键；返回设备 ID、代次、成本和下次免费时间 |
| `GET /v1/distributions` | 最近 100 条本账号已完成且仍有权益的分发清单；不包含下载 URL |

公钥与硬件指纹属于客户端输入。硬件指纹只作为元数据存储，不授权登录或自动恢复。激活必须由用户明确确认替换设备，再提交签名挑战。

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
| `GET /v1/admin/audit` | 最近 100 条审计记录 |

管理 API 是受控后端集成接口。没有独立操作员账号、MFA 或完整可视化后台；当前审计管理员统一记为 `admin`。正式运营应在上层实现有具体身份的授权代理，不让多人共享根密钥。

0.2.0 的 `importEntitlement`、`hasReleaseAccess` 和 `bestUpgradeOffer` 是受控宿主服务方法，没有新增用户自报证据的公开 HTTP 路由。用户 profile 的历史授权 `order_id` 可以为空，并返回按版本保存的 `channels`；消费者不能假设所有权益都来自订单。

完整请求示例见 `examples/demo.mjs`，覆盖真实本地 HTTP 请求和客户端验签。各时间字段除签名许可证的 `iat/nbf/exp` 为 Unix 秒之外，均为 Unix 毫秒。

## 设备自助重置

`GET /v1/devices/:groupId/reset` 需要用户 Bearer 会话，返回 state、generation、freeAt、credits、cost、canReset；预览不扣额度。`POST` 同一路径需要 `{generation, cost, confirm:true}` 和 Idempotency-Key；cost 为 free 或 credit。仅能操作当前登录账号的设备组。状态、代次或费用变化会拒绝确认。

`deviceResetStatus` 与 `resetDevice` 也可由可信宿主直接调用。成功重置停止旧设备续期，作废旧挑战，消费免费机会或一次额度并开始新的自然月冷却。后续一次激活返回 cost=reset，不再扣费、不重新延长冷却。绑定 profile 增加 reset_pending 字段。已签发许可证保持原到期时间，不能远程撤销离线副本。
