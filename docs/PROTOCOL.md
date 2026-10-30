# 客户端协议

## 密钥

服务器签名密钥和每个客户端的设备密钥是独立的 Ed25519 密钥对。没有所有客户端共用的签名秘密。服务端仅保存设备公钥。Node SDK 是参考实现，生产本地应用需自行选择平台安全密钥存储和恢复策略；首版不包含 Windows TPM 适配器。

公钥交换使用 PEM 包装的 SPKI。公钥指纹为 SPKI DER 字节的 SHA-256 小写十六进制。硬件 digest 与公钥指纹是不同概念。

## 挑战

服务端返回 UTF-8 `message` 字符串，格式为 JSON 数组：

```text
["product-license-kit",1,kind,challengeId,accountId,payload,randomNonce]
```

客户端必须对收到的 message **原始 UTF-8 字节**进行 Ed25519 签名，不重新格式化 JSON。签名使用无填充 base64url。协议版本和 kind 必须符合当前交互；只为可信服务器和用户主动发起的操作签名。不要跨产品无条件复用同一设备私钥。

激活挑战通过用户会话申请，payload 固定设备组、公钥及指纹。授权挑战固定设备、收费版本和绑定代次。挑战只能消费一次，服务器时间决定有效期。

## 签名信封

许可证为 JWS 风格 compact 编码：`base64url(header).base64url(payload).base64url(signature)`。算法固定 EdDSA，使用 Ed25519。header 的 `typ` 为 `plk-license` 或 `plk-distribution`；`kid` 是服务端 SPKI SHA-256 前 24 个字符。

许可证声明：

```json
{
  "iss": "deployment-issuer",
  "aud": "product-id",
  "sub": "internal-account-id",
  "edition": "edition-id",
  "device": "device-id",
  "keyThumbprint": "sha256-of-device-spki",
  "generation": 1,
  "ownership": "perpetual",
  "iat": 1800000000,
  "nbf": 1800000000,
  "exp": 1800000900
}
```

客户端同时校验签名、算法、type、kid、issuer、产品、版本、账号、设备、公钥指纹和时间范围。验签公钥必须由已信任的产品配置或受保护的更新链预置。不能从与许可证相同的任意响应中取一个新公钥就直接信任。

默认无时钟偏移宽限；时钟错误应提示联网校时。恶意回拨本地时钟和修改客户端不能仅靠本地验证解决。高价值的服务端功能仍应在服务端授权。

`generation` 是绑定代次，服务端签发时核对当前值。离线验证者不知道实时撤销状态；不要把存在该字段描述成即时离线撤销。密钥轮换首版采用部署流程和客户端可信公钥更新，不内置远程动态信任新密钥。

## 文件分发

分发标记不含登录令牌，不能用于申请设备许可。签名清单固定分发 ID、收费版本、构建 ID 和最终文件 SHA-256。SDK 验证清单签名、预期范围和文件实际哈希。清单不会自动证明水印已经嵌入：文件处理适配器必须独立验证这一点。

个性化完成后再做平台签名，之后计算最终哈希。Windows EXE 不应使用示例中的附加 JavaScript 注释方式处理。真正的 EXE 处理器需在对应文件结构中嵌入标记、签名、验签并完成兼容性测试。

## 重置后重新绑定

用户通过宿主或 Bearer API 预览并确认重置。服务端复查绑定代次、费用和账号状态，旧绑定停用并递增代次，失效该组未完成挑战，记录已支付的一次重新绑定。设备仍按正常 enrollment → 私钥签名 → activate 流程激活，不可用 HWID 直接获取授权。首次重绑消费待绑定状态，之后再次换机重新检查冷却与额度。
