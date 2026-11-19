# PostgreSQL 用户中心与独立管理端

核对日期：2026-11-19。本文描述已合入 main 的源码 0.7.0，不表示已创建版本标签、发布 npm 包或完成生产部署。SQLite 当前迁移为 8；PostgreSQL 使用独立迁移 1–6、共 41 表。当前能力与外部验收边界见 [演进计划](ROADMAP.md)。

门户与 Bot 已有本地实现，真实 KOOK OAuth 资格和目标部署仍未验收。普通门户换绑沿用核心自然月／额度规则；产品见证恢复是单独的宿主政策。

`PostgresPortal` 与 `createPortalApp` 提供可复用的同源浏览器服务：OAuth 跳转、首次验证器设置、MFA／恢复码登录、用户权益与订单、明确换绑预览，以及具名权限的独立 `/admin` 页面。`examples/portal-server.mjs` 是完整启动入口。用户账号必须先通过可信邀请流程注册；不把首次访问者自动设为管理员，不接受请求中的“已验证身份”，不实现公开的 MFA 解除入口。

这是通用框架的可选 PostgreSQL 适配层，要求与 `AsyncFramework` 共用同一个根仓储。同步 SQLite API 和 EXAMBIA 产品原有网页继续使用各自入口；没有把 EXAMBIA 的身份组、见证恢复或收款策略移入公共框架。门户阶段迁移 5 增加七张表，当时共 35 表；当前 Bot 阶段已追加迁移 6，共 41 表，旧迁移摘要保持不变。

## 配置与启动

先用数据库迁移身份将独立 schema 升级，再用运行身份启动服务；运行身份需门户七表、框架会话／审计及授权业务所需的 DML，迁移历史只需 SELECT。远端 PostgreSQL 始终验证 TLS CA 与主机名；API 与门户应通过受控 HTTPS 入口分别发布。浏览器不接触机器管理密钥或原生 bearer token。

私有配置示例，所有文件相对配置文件目录解析：

```json
{
  "connectionString": "postgresql://portal_runtime:PRIVATE_PASSWORD@db.example/framework",
  "schema": "plk",
  "caFile": "postgres-ca.pem",
  "migrate": false,
  "host": "127.0.0.1",
  "port": 3200,
  "origin": "https://licenses.example",
  "issuer": "your-existing-issuer",
  "namespace": "customer-portal",
  "catalogPath": "catalog.json",
  "keyFiles": ["private/signing.pem"],
  "portalKeyFile": "private/portal.key",
  "kookClientId": "YOUR_PLATFORM_CLIENT_ID",
  "kookSecretFile": "private/kook-client-secret.txt"
}
```

门户加密钥是独立的 32 字节随机二进制文件，不是十六进制文本，也不是服务端 Ed25519 签名钥。通过受控脚本使用 `crypto.randomBytes(32)` 创建新私有文件，并独立保管恢复口令。入口会保护配置与密钥权限；不会自动创建实际业务目录或搜寻 `.env`。不要直接替换门户钥，已有加密 MFA 材料和上下文会因此拒绝启动；门户钥迁移须另行设计与审核。

如果共用的签名策略设置了部署摘要，增加同一个 `signingContextHash`，并在 `keyFiles` 提供现役及准备钥；否则签发按既有缺钥／上下文规则拒绝。更换授权签名钥不等于更换门户加密钥。

```powershell
$env:PLK_PORTAL_CONFIG_FILE = '你的私有配置绝对路径'
pnpm build
node examples/portal-server.mjs
```

KOOK 回调配置为 `origin + /auth/callback`。只有真实平台开通 OAuth、Client ID／Secret 和回调条件后，才能完成实际平台验收。本地检查使用独立模拟身份平台；本项目当前真实 KOOK OAuth 尚未开通，未据模拟结果宣布实传通过。

首次操作员必须是已注册、已确认的账号。可以在私有配置临时加入：

```json
"bootstrapOwner": {
  "accountId": "经核实的账号 UUID",
  "reason": "approved initial operator bootstrap"
}
```

该项授予全部已知门户权限，只能初始化空名单；不覆盖已有名单。初始化后从部署配置移除，后续通过具名后台调整。启动时提交与现有授权不符的 bootstrap 会拒绝，而非重置权限。没有默认账号、默认密码或“首位登录者拥有管理权”。

## OAuth、MFA 与会话

登录先建立五分钟的随机 state 和独立浏览器 nonce，只保存摘要。回调核对发起浏览器，并在调用身份平台之前原子消费 state；丢失提交回执不重放授权码交换。已注册账号进入待 MFA 状态。平台身份验证和外部 I/O 均在业务事务之外，禁止因数据库重试重复调用平台。

待 MFA 和活动会话均关联框架会话，因此账号停用、身份变更或安全撤销会使旧浏览器资格一并失效。框架 bearer 仅加密保存在后端；浏览器拿到的是另一枚随机 HttpOnly Cookie。MFA 通过后更换 Cookie、CSRF 和框架会话，旧凭证失效。

首次设置支持二维码和手动密钥。TOTP 使用 SHA-1、六位、30 秒和前后各一窗口；同一计数器不能再次消费。密钥使用独立门户钥做 AES-GCM 加密，并绑定 namespace／账号或准备会话。十个 192 位恢复码只显示一次，数据库仅保留摘要；每码单次消费，跨节点并发只允许一个成功。重新生成恢复码须提供新的 TOTP，旧码同时失效。源密文损坏或钥不符时拒绝，不重新生成身份。

| 会话 | 总期限 | 空闲限制 |
| --- | --- | --- |
| OAuth／待 MFA | 5 分钟 | 不延长 |
| 普通用户默认 | 12 小时 | 不因短暂空闲退出 |
| 勾选保持登录 | 30 天 | 总期限不滑动延长 |
| 有管理权限的操作员 | 自本次 OAuth 起最多 2 小时 | 30 分钟 |

敏感写入另要求五分钟内验证 MFA；管理权限刚新增或调整后，需要不早于授权变动时刻的 MFA。旧普通会话不会因后来获授权限就自动取得新管理能力。普通用户可见会话到期时间，Cookie 用途、期限及必要性有页面说明；无广告、分析脚本或 localStorage 凭证。此技术边界不代替运营方自己的隐私告知及法规评估。

每个账号共享十次／五分钟 MFA 尝试预算；HTTP 还使用 PostgreSQL HMAC 限流。普通查询不会复活已过期的工作人员空闲期限。服务端时间取 PostgreSQL，部署仍需保持应用／数据库时钟同步。

## 权限与写入

权限独立为 `accounts.read`、`accounts.write`、`entitlements.write`、`credits.write`、`invitations.write`、`payments.confirm`、`audit.read`、`operators.write`。后台只展示相应表单，服务端每次重新检查当前账号、会话和权限，不信任前端显隐。最多 100 名操作员；授权修改有 revision，不能从旧页面覆盖新授权，必须保留至少一名仍可用的权限管理者。门户禁止直接停用现役权限管理者，须先调整其角色并保留其他负责人。

具名授权、操作原因和业务结果审计与核心业务同事务提交。核心历史审计仍保留原结构，新增 `portal.admin.*` 关联实际操作员账号；审计失败不会留下已扣额度、已确认权益或已消费意图。不会由浏览器代持部署管理 token。

人工核款需 `payments.confirm`、近期 MFA、目标账号／订单匹配、金额／币种／凭据和明确确认勾选。此入口登记已核对的人工到账，不能发起资金操作，也不是商户回调验签或自动退款适配器。邀请票据仍绑定指定 provider／subject、单次使用，由受信任注册入口交接；不会自动向外部用户发消息。

`/v1` 原生 API 仍有自己的设备证明、用户 bearer 和部署管理边界；门户 MFA 不会被宣传为所有原生协议额外增加了第二因子。原有产品后台也不会因 vendor 包同步自动改用该角色表。

## 换绑确认

用户先请求只读资格预览，看到当前设备、代次、自然月免费日期、可用次数及本次 free／credit 费用。仅在明确勾选后才提交确认。服务端意图有效五分钟，绑定 namespace、当前 Cookie 和完整资格快照；不同账号／会话、代次或费用变化均拒绝。确认和结果回执同事务；同一意图并发／重复确认只扣一次，丢失提交回执可查询同一意图结果。

成功后页面重新读取真实业务状态，同时更新余额、免费日期和“等待新设备绑定”，不保留旧余额制造矛盾。重新验证 MFA 会更换会话并使旧意图失效。此能力沿用原自然月冷却及额度规则，不等于新增见证免费恢复政策。

## 浏览器接口

全部写入需精确 Origin、JSON 和会话 CSRF（登录发起只需 Origin／JSON）。Cookie 在 HTTPS 使用 `__Host-`、Secure、HttpOnly、SameSite=Lax，Path=/，无 Domain；仅回环 HTTP 开发可不设 Secure。禁止缓存、第三方脚本、嵌入和任意跳转；日志去掉查询串及认证头。

| 入口 | 用途 |
| --- | --- |
| `POST /api/auth/start`、`GET /auth/callback` | 授权发起和服务端回调 |
| `GET /api/session`、`GET /api/setup-qr` | 当前阶段／CSRF；仅待设置会话可取二维码 |
| `POST /api/auth/mfa`、`/api/auth/recovery-codes`、`/api/auth/logout` | 验证、恢复码轮换、退出 |
| `GET /api/profile`、`/api/orders`、`/api/distributions` | 当前账号视图；列表支持稳定游标 |
| `POST /api/orders` | 带命令幂等键创建订单 |
| `POST /api/devices/reset-preview`、`/api/devices/reset-confirm` | 明确的两步换绑 |
| `GET /api/admin/account/:id`、`/api/admin/audit`、`/api/admin/operators` | 按权限查询 |
| `POST /api/admin/actions/:action` | 受保护的具名写入 |

提交结果不明返回对应 UNCERTAIN 错误，不建议盲目重放。MFA 完成但 Cookie 回执丢失时应重新做 OAuth，使用下一个有效 TOTP 或剩余恢复码；不得据此删除 MFA。换绑使用原意图／幂等结果核查。前端不会自动重复写入。

## 备份与恢复

`backupPostgres`／`postgresSigningBackup` 的 `portalKeys` 必须覆盖所有已初始化门户 namespace，元素为 `{namespace,key:Uint8Array}`。备份验证每把钥的 SHA256 与 `portal_settings.key_hash` 相符，缺少或错误直接拒绝，避免形成无法解密 MFA 的备份。现役签名私钥、门户钥和完整数据库共同进入 AES-GCM 加密包，重新读取核对后才有回执。总文件数仍最多 32；多门户／多私钥配置应核对该上限。

`examples/postgres-server.mjs` 的私有 `backup` 可增加 `portalKeys:[{namespace,keyFile}]`。运行门户的共享数据库若未给轮换控制进程提供对应钥，自动签名轮换会停在备份失败处，不能跳过恢复材料校验。

恢复仅进空 schema，并清除原会话、OAuth state 和换绑意图；MFA、恢复码摘要、操作员及付费业务保留。门户钥文件名为 `portal-<namespace 的 SHA256 前 24 位>.key`；只在私有恢复流程中从加密包取出，并使用同一 issuer／origin／namespace 的审核配置，不自动落盘或启动服务。已耗尽的旧限流窗口保持封闭到原到期时刻，恢复后立即登录可能暂时收到 429；不能为方便而清空生产预算。

恢复演练、目标服务器部署、真实平台 OAuth 和客户验收仍须分别完成。本地模拟未改变生产配置、导入产品数据或发送实际通知。

算法依据：[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)、[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226)。测试包含标准向量、真实 PostgreSQL 的并发／故障／备份恢复，以及实际浏览器的授权、MFA、保持登录、换绑和具名审计。

门户阶段最终本地验证：框架与 vendor 各 87 项 PostgreSQL 检查、97 项默认回归通过；产品生产构建及 481 项测试通过。C# 30 项本地／76 项 PostgreSQL HTTP 检查、Rust 五项测试／77 项 HTTP 检查通过。两处 133 个框架文件哈希一致；新增迁移 5 后共 35 表，旧迁移 1–4 摘要不变。该阶段真实 OAuth、生产切换和通用 Bot 交互包尚未交付；随后 Bot 已实现，当前外部条件见 ROADMAP.md，综合手册随本次文档刷新更新。

随后 Bot 阶段追加迁移 6，当前为 41 表，旧迁移 1–5 摘要不变。[Bot 交接](BOT.md#注册进入门户) 为 `/api/auth/start` 增加可选 `registration`，必须显式配置 `registrationAdmission`。仅接受此门户命名空间的一次性、指定 KOOK 身份、当前 epoch 的交接；授权后仍需 MFA，不能从旧原生注册接口旁路。参考启动入口的可选 kookBot 对象同时提供网页注册准入函数，缺省 Bot 执行与投递关闭。以上 87／97 是前一阶段的历史数量，不表示新增分支的验证已被自动涵盖。
