# Shadowrocket Routing Skill

面向 Codex 的中文 Skill：维护 **国内直连、国外 AI 走代理、代理故障时保持系统阻断**，并保留当前出口、所有端口与其他订阅。

这是脱敏的维护指南与配置片段，**不是 VPN 服务，也不自带系统防火墙安装器**。安装 Skill 或导入片段不等于完成断线防泄露保护。

## 内容

- [Skill 入口](skills/shadowrocket-ai-routing/SKILL.md)：检查、合并配置、节点同步与最少量验证。
- [分流片段](skills/shadowrocket-ai-routing/assets/routing-fragment.conf)：国内 DoH、国外 AI 优先代理、微信/网易等直连、最终代理。仅用于合并，不整份覆盖已有配置。
- [维护说明](skills/shadowrocket-ai-routing/references/operations.md)：PF 与应用规则的职责、更新节点、timeout、回退、iPhone/Tailscale 边界。
- [历史案例](skills/shadowrocket-ai-routing/references/verified-case.md)：UU 远程与公众号恢复的用户确认，以及早期故障实测的有限证据。

## 安装和使用

把 `skills/shadowrocket-ai-routing` 整个文件夹放入 Codex 技能目录（通常为 `~/.codex/skills/`；已有同名技能时先备份）。让 Codex 重新发现技能，然后使用：

```text
使用 $shadowrocket-ai-routing 排查国内服务打不开，保留当前出口、全部端口、订阅和断线阻断；只验证受影响服务。
```

也可请求检查节点更新后的白名单同步。Skill 会先发现现有安装；缺少 PF/同步器实现时，应报告缺失，不能声称自动安装或已经验证。

## 核心约束

1. 国外 AI 规则优先 PROXY，国内服务与国内 AI 按规则 DIRECT，未知目标最终 PROXY。
2. 国内普通解析使用国内加密 DNS，避免依赖故障代理；保留 UDP 不支持时 REJECT。
3. 系统阻断独立于应用分流。国内域名与物理 IP 白名单可能不一致，境外 CDN 或远控对端需具体排查。
4. 节点同步失败保持上一有效规则，不自动开放公网直连。切订阅时保留活动配置与守护服务。
5. 保留真实出口、协议、端口、其他订阅与系统根规则；不把修复扩大成全局重置。
6. 只做与变更有关的验证。主页连通不能替代文章/远控；历史 IPv4 报告不能扩大为所有未来场景的保证。

本仓库没有节点凭据、订阅链接、私人出口/节点地址、设备标识、抓包或原始日志。手机 Tailscale 共存说明不代表手机已有 macOS PF 的同等保护。

## 验证范围

Skill 已通过创建工具的格式校验与离线内容审查。配置片段依据一次已生效的 macOS 配置整理，不是逐台设备验证过的独立完整配置。维护期间不应仅为阅读或安装此 Skill 中断现有网络。
