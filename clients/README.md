# C# 与 Rust 客户端 SDK

核对日期：2026-11-19。SDK 源码已随框架 PR #19 合入，尚未发布包。2026-11-18 的 Windows x64 本地及回环 HTTP 数量为带日期证据；未将产品 TPM 或其他系统兼容性据此标为通过。协议见 [客户端协议](../docs/PROTOCOL.md)，当前框架边界见 [演进计划](../docs/ROADMAP.md)。

工作区 SDK 源码版本为 0.1.0，使用框架 0.7.0 的 `/v1/` 设备协议；未发布 NuGet 或 crates.io 包。C# 项目为 .NET 10，Rust 项目使用 Rust 1.100，依赖锁文件随源码保留。授权服务器签名固定为 Ed25519，设备支持 Ed25519 或 RSA-2048/PSS-SHA256；RSA 指数为 65537、盐长为 32 字节。

两种 SDK 提供请求客户端、精确范围的挑战签名、许可证及分发清单验证、Windows 当前用户 DPAPI 软件密钥存储和 SMBIOS 摘要。C# 接受持有签名权限的 `RSA` provider；Rust 接受自有的 `rsa::PrivateKey`。TPM 证明、制造商信任、OAuth 浏览器交接和操作许可属于宿主协议，不能由 RSA 签名通过推断硬件可信。EXAMBIA 仍使用其现有 C# 产品协议与身份目录，本 SDK 不迁移或替换那些身份。

## 密钥与硬件摘要

`WindowsKeyStore.LoadOrCreate` 与 Rust `windows::load_or_create_key` 共用格式。默认目录为当前用户 LocalAppData 下的 `ProductLicenseKit/Identity/<产品 ID 的 SHA256>/<账号 UUID>/device.key`。私钥为随机 Ed25519 seed，以 DPAPI CurrentUser 加密，附加熵固定产品与规范账号 UUID。目录 ACL 只允许当前用户，拒绝路径中的重解析点。两种语言共用独占文件锁，原子提交时不覆盖已有身份；无法解密、文件损坏或身份缺失后的已知绑定问题必须由宿主明确处理，不消费换绑次数或自动恢复旧绑定。

创建身份必须显式允许：C# 的 allowCreation 默认 false，Rust 必须传入 allow_creation。已有绑定正常加载时保持 false，缺少文件立即返回 DEVICE_KEY_NOT_FOUND；宿主核实是首次建立身份或用户已明确办理新绑定时才传 true。即使允许创建，现有损坏文件也不会被替换。自定义 storageRoot 应由宿主指定，不能直接使用远程请求中的路径；它适合隔离测试和应用私有目录。

`HardwareIdentity.ReadWindows` 与 Rust `windows::read_fingerprint` 读取 RSMB 原始 SMBIOS，在唯一有效的 type-1 UUID 上计算摘要。不使用 MAC、随机数或通用占位符作为回退；原始固件数据不写入 SDK 文件。摘要输入为 UTF-8：`product-license-kit-hwid-v1\0<productId>\0<schema>\0uuid:<原始 16 字节的小写十六进制>`。产品及 schema 分离；这是一项设备信号，不能证明 TPM 或防止克隆。

## C# 接入片段

```csharp
using ProductLicenseKit;

using var key = WindowsKeyStore.LoadOrCreate(productId, accountId, allowCreation: firstUseConfirmed);
var fingerprint = HardwareIdentity.ReadWindows(productId, "my-hwid-v1");
using var api = new LicenseClient(serverOrigin);
var challenge = await api.RequestAsync("/v1/devices/challenges", new {
    groupId, publicKey = key.PublicKey,
    fingerprint = new { schema = fingerprint.Schema, digest = fingerprint.Digest }
}, accessToken);
var signature = key.SignEnrollmentChallenge(challenge.GetProperty("message").GetString()!,
    new EnrollmentContext(challenge.GetProperty("challengeId").GetString()!, accountId, groupId, fingerprint));
var binding = await api.RequestAsync("/v1/devices/activate", new {
    challengeId = challenge.GetProperty("challengeId").GetString(), signature
}, accessToken, Guid.NewGuid().ToString("D"));
```

创建 `LicenseScope` 时填写产品配置中的 issuer、产品、收费版本、当前账号与设备、公钥、硬件摘要、渠道和已知 generation。`VerifyLicense` 使用可信产品配置中预置的服务端公钥；不能把 `/v1/signing-key` 的任意响应直接作为信任来源。默认检查当前 UTC 时间，未配置时钟宽限。调用方可明确传入时间以执行隔离测试。

## Rust 接入片段

```rust
use product_license_kit_client::{LicenseClient, windows};

let key = windows::load_or_create_key(product_id, account_id, None, first_use_confirmed)?;
let fingerprint = windows::read_fingerprint(product_id, "my-hwid-v1")?;
let api = LicenseClient::new(server_origin)?;
// 用账号会话申请挑战，再把原始 message 与已知账号、组和摘要交给 sign_enrollment。
// license 挑战使用 sign_license，最终用预置公钥、LicenseScope 和 UTC 秒调用 verify_license。
```

Rust HTTP API 为阻塞调用，应放在工作线程；不要在 Tokio 的异步执行线程直接调用。C# 使用异步请求。两种实现只允许 HTTPS 或明确的本机 HTTP，禁止凭据随重定向转发，不自动重试请求。单次超时十秒、请求 JSON 最多 16 KiB、成功响应最多 1 MiB，拒绝重复 JSON 字段、非规范编码、未知声明及不匹配范围。重试幂等业务命令时沿用同一个 Idempotency-Key；一次性挑战不能盲目重放。

## 本地验证

```powershell
pnpm check
pnpm test:clients
pnpm audit:source
```

需要 .NET 10 SDK、Rust/Cargo、rustfmt、Clippy；Windows Rust 需要 MSVC 工具链。可用 `pnpm test:clients dotnet` 或 `pnpm test:clients rust` 选择语言；Windows 上验证 Rust 时仍会构建 C# 测试程序，用于双向 DPAPI 互读与原始平台信号的一致性检查。`PLK_DOTNET` 和 `PLK_CARGO` 可指定工具绝对路径。测试创建独立临时账号目录、内存数据库及回环 HTTP 服务，结束后检查范围并清理，不接触生产账号、TPM、系统信任或支付平台。

HTTP 联调实际完成注册、合成订单核款、两种设备算法激活、签发、重放拒绝、范围和时间检查、文件哈希、会话退出、重定向及固定／分块超大响应拒绝。Windows 还用 C# 创建的 DPAPI 身份在 Rust 中完成真实挑战签名，再用 C# 读取 Rust 创建的身份并检查文件 ACL；两端独立读取本机 SMBIOS 后核对摘要。

后续同一套 C# 76 项、Rust 77 项 HTTP 检查也在 AsyncFramework／PostgreSQL 18.7 后端通过。设置 `PLK_POSTGRES_BIN` 后执行 `pnpm test:postgres -- --native`，脚本创建并清理自己的回环测试数据库，随后构建两种客户端并验证；不读取默认生产连接串。详见 [PostgreSQL 验收](../docs/POSTGRESQL.md)。默认 `pnpm test:clients` 继续使用内存 SQLite。

2026-11-18 验收环境为 Windows NT 10.0.26300.0 x64、.NET SDK 10.0.403、Rust 1.100.0。C# 30 项本地检查、76 项 HTTP 检查；Rust 5 项测试、77 项 HTTP 检查通过，Rust 格式和 Clippy 严格检查通过。框架与产品 vendor 各 82 项回归通过，93 个源文件的运行文件／已识别凭据模式审计通过，两者本轮变更的 41 个文件哈希一致。其他系统尚未执行原生 SDK 验收。

NuGet 扫描及 cargo-audit 0.23.0 未报告已知漏洞；Cargo.lock 的审计依赖数为 154，警告为空。RustSec 数据库版本为 `233155b4025b854c68a4b199c0e32d7fd53291a2`，更新时间为 2026-11-17 18:14:35 +08:00。扫描结果属于该次数据库快照。可分别用 `dotnet list clients/dotnet/ProductLicenseKit/ProductLicenseKit.csproj package --vulnerable --include-transitive --no-restore` 和 `cargo audit --file clients/rust/Cargo.lock` 重新核对。

实现参考：[Rust 安装与 Windows 工具链](https://rust-lang.org/install)、[reqwest 阻塞客户端](https://docs.rs/reqwest/0.13.5/reqwest/blocking/)、[RustCrypto RSA](https://docs.rs/rsa/0.10.0/rsa/)、[DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)、[SMBIOS 读取](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable)。
