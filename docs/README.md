# 文档导航

更新日期：2026-10-31。当前源码版本 0.2.0；发布状态与功能边界以系统手册为准。

| 文档 | 内容 |
| --- | --- |
| [系统手册 Markdown](SYSTEM-GUIDE.md) / [Word](SYSTEM-GUIDE.docx) | 完整功能、架构、权益、设备、接口、运维与交付状态 |
| [架构与规则](ARCHITECTURE.md) | 对象、事务、自然月、历史授权与 Beta |
| [HTTP API](API.md) | 认证、参数、路径与幂等 |
| [适配器接入](INTEGRATION.md) | 身份核实、历史凭证、支付、通知与文件 |
| [客户端协议](PROTOCOL.md) | 设备密钥、挑战、签名许可证与分发清单 |
| [部署维护](OPERATIONS.md) | 配置、迁移、备份恢复与轮换 |
| [仓库治理](REPOSITORY.md) | 分支、发布与文件边界 |
| [演进计划](ROADMAP.md) | 已实现能力和后续候选 |

## 同步维护 Markdown 与 Word

SYSTEM-GUIDE.md 是手册的唯一内容源。用独立文档环境安装 python-docx 后执行：

```sh
python scripts/export-guide.py
python scripts/export-guide.py --check
```

生成器仅依赖 python-docx 与 Python 标准库，不增加产品运行时依赖。它将规范化换行后的 Markdown SHA-256 记录在 Word 元数据，并核对正文次序与内容；格式检查不替代渲染后的逐页排版检查。提交 Markdown、DOCX 和相关详细文档，渲染中间产物留在仓库外。
