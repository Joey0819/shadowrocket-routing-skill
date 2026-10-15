# Shadowrocket Routing Skill · 2.0

面向 Codex 的中文 Skill 与可迁移 macOS 组件：**国内直连、国外 AI 走原代理、故障时系统阻断直连**，保留原出口、端口与订阅。

## 包含什么

- [Skill 入口](skills/shadowrocket-ai-routing/SKILL.md)：识别、安装、维护与最少量验证流程。
- [完整安装指南](skills/shadowrocket-ai-routing/references/install.md)：另一台 Mac 的授权、分流合并、安装计划、PF 安装、验证和回退。
- [迁移 CLI](skills/shadowrocket-ai-routing/scripts/portable_guard.py)：发现真实端口/VPN/网卡、动态节点计划、系统服务、白名单同步与故障验证。
- [沙盒节点助手](skills/shadowrocket-ai-routing/assets/node-sync/NodeSync.swift)：用户授权后只读节点数据，无网络权限，无固定用户目录写入例外。
- [分流片段](skills/shadowrocket-ai-routing/assets/routing-fragment.conf)与配置合并器：国内 DoH、微信/网易等直连、国外 AI 优先代理、最终代理。
- [维护与边界](skills/shadowrocket-ai-routing/references/operations.md)、[历史案例](skills/shadowrocket-ai-routing/references/verified-case.md)。

## 在另一台 Mac 使用

将 `skills/shadowrocket-ai-routing` 文件夹安装到 Codex 技能目录（通常为 `~/.codex/skills/`，已有同名技能时先备份），然后请求：

```text
使用 $shadowrocket-ai-routing 在这台 Mac 配置国内直连、国外 AI 代理与断线阻断，自动识别端口和节点，保留当前出口和其他订阅。
```

先读[安装指南](skills/shadowrocket-ai-routing/references/install.md)。支持 macOS 13+；需要 Python 3.9+ 与 Apple Command Line Tools。必须在目标 Mac 首次授权节点目录，并为 PF/系统服务提供管理员授权。Skill 本身、VPN 开关或导入配置不代表保护已经通过验证。

可从 [Releases](https://github.com/Joey0819/shadowrocket-routing-skill/releases) 下载带实际通用 App 的迁移包；也可在仓库根目录构建：

```sh
python3 tools/build_release.py
```

发布包包含 arm64/x86_64 App、源码、Skill、文件校验清单和外部 SHA256。App 为 ad-hoc 签名、未公证；不要关闭系统安全保护来运行。目标 Mac 可从源码构建后自行批准。

## 重要约束

- 安装器不会直接写厂商私有数据或改节点/订阅；活动分流通过 Shadowrocket UI 备份、合并、编译与确认。
- 识别真实 loopback listener，不固定用户名、UID、端口、节点数量或出口 IP。SOCKS5 是否为链式出口不能仅靠元数据推断，首次需核对一次，之后普通受支持节点按原端口自动同步。
- AI 拒绝先于国内/入口例外，境外公网默认拒绝；目录读取、DNS、候选校验失败时保留旧规则。节点启动解析用独立国内加密 DoH，AI 地址维护仍走代理。
- 遇到旧版保护、自定义 PF 或其他同时连接的 VPN，停止初装并审阅，不覆盖或自动卸载。系统 PF 影响物理网络，境外 CDN/远控对端可能需单独适配。
- 不承诺识别所有未来 AI 目标、服务器地理位置或所有系统启动阶段。IPv4/IPv6、故障阶段与实际用户操作的证据分别报告。

## 验证与开发

```sh
python3 -m unittest discover -s tests -v
python3 tools/build_release.py
```

测试不需要 sudo，不修改真实分流、不启停 VPN、不激活 PF。macOS 上额外使用实际 PF 解析器校验候选语法；构建会检查实际签名 App 的节点解析、窗口生命周期及发布包解压后的签名/校验值。

开发机的只读发现已识别正在使用的监听端口，并检测到已有旧保护，因此未安装第二套规则。尚未在另一台物理 Mac 完成管理员安装和物理抓包；首次安装必须运行目标机验证，不能复用历史报告。

本仓库不含真实节点/出口地址、订阅链接、节点凭据、用户目录、设备标识、抓包或原始日志。测试地址、端口、用户路径为合成夹具；本机生成的计划/日志/发布产物默认忽略。
