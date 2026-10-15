# 维护与排障

## macOS 系统保护

| 层级 | 作用 | 不能据此宣称的结果 |
| --- | --- | --- |
| 活动配置 | 域名/IP 分流、DNS、UDP 回退 | 退出客户端后的系统阻断 |
| 系统 PF 和守护服务 | 物理出口限制、代理入口、国内目的地例外 | 按应用身份识别全部 AI 或未来 CDN |
| 节点同步助手 | 授权读取非凭据元数据，供入口更新 | 每个节点或每个订阅始终可用 |

已有安装可能使用 `ShadowrocketEgressGuard`、`ShadowrocketNodeSync`、`local.shadowrocket.egress-guard`、`local.shadowrocket.node-sync` 等名称。这些仅为发现线索，必须核对实际安装与来源；本仓库不提供这些程序。

### 检查与修改

1. 只读发现服务、监听端口、活动配置、节点与 PF 接入点。不需管理员的状态读取不请求 sudo；PF 读取受限时说明用途再请求。
2. 核对已安装脚本支持的动作、来源、所有权与回退，不照搬历史 `sudo ... guard.py ...` 路径。
3. 保留系统根规则及其他软件 anchor。不得 `pfctl -F all`、覆盖整个 `/etc/pf.conf` 或关闭 PF 来修应用问题。
4. 白名单限目的地址、协议和必要端口；AI 拒绝先于国内/入口例外，A→B 中的 B 不获物理直连。注意浮动 state 可能让 TUN 状态授权物理流量。
5. 国内分类数据有来源、更新时间与合理性校验。APNIC 是地址资源分配数据，不是实时定位；更新失败保持上一有效规则，不把空数据解释为允许所有流量。
6. 回退只恢复本方案改动的文件/anchor。单个国内规则回退不应卸载断线保护；完整卸载不是默认修复。

### 边界

PF 过滤地址/协议，不能保证所有 AI 版本都不产生任何直连流量。国内 IP 放行本身会允许去往这些地址的连接，已知 AI 地址拒绝也不等于按应用身份阻断。新地址、共享 CDN、其他 VPN、已有状态及系统升级需要按变化检查。

国内域名可能使用境外 CDN，远控也可能连接境外对端；它们会被严格目的地白名单挡住。先定位域名、解析、策略和地址，再决定限定例外或代理；不要放开共享云网段。国内 AI 在本策略中允许直连。

配置控制出站路径，不能保证平台不会从账户/浏览器等其他信号判断地区。

## 新订阅与节点更新

核对链路：**节点来源 → 只读快照 → 守护服务验证 → PF 候选 → 原子替换**。

- 只读取用户授权的精确目录，不以 root 或其他进程绕过应用目录隐私限制。
- 元数据仅保留来源分类、显示名、主机、协议、原端口/范围等必需项。公开分享再去除个人名称与真实地址，不输出密码、UUID、订阅链接或完整归档。
- 检查快照时间、结构、数量及协议完整性。`schema_unconfirmed`、零节点、目录错误、解析失败时保留旧规则。
- DNS 变化需更新入口地址；不永久固定过期 IP。白名单成功不是服务端协议/凭据成功。
- 切换订阅一般保留活动规则；切全局直连/代理、启用其他配置、关闭服务、改用 Clash、迁移机器会改变前提。不能承诺「永远自动生效」。

## 国内服务打不开

优先用户报告的一两个失败服务与一次实际操作。

| 观察 | 下一步 |
| --- | --- |
| 微信已有 DIRECT，文章仍失败 | 核对实际文章、图片/跳转域名、DNS、PF；不反复添加 qq.com |
| 未列国内域名依赖境外 DNS | 检查 `dns-server`，不只改 `direct-dns-server` |
| DoH/HTTP3 路径不稳定 | 核对当前版本支持后，仅给该 DoH 加 `#no-h3` |
| 网易主页通，UU 客户端失败 | 查实际依赖、UDP 与对端；主页不能代替远控验证 |
| DIRECT 地址属于境外 CDN | 对照物理白名单；不关闭默认拒绝或放行任意 443 |
| 用户确认恢复 | 记录用户确认，不再全订阅测速或无关断网 |

`proxy-dns-server` 用于节点域名解析，普通代理请求通常由代理端解析。改 DNS 前核对版本语义、Hosts 与代理协议，避免产生启动依赖环。

## 节点 timeout

依次区别过期 Host、当前解析、入口白名单、协议/端口、服务端与凭据、测速方法。

- CONNECT 与纯 TCP 测速意义不同；UDP 节点不能用 TCP 结果替代。
- TUN 可能截获 socket 探测。即使用 interface bind，也不凭虚拟来源和 socket 成功认定物理已到服务器。
- 不为诊断修改原节点端口或刷新无关订阅；若获授权临时切换测试，结束恢复原选择。

## 故障阻断验证

仅在修改系统保护、链路/同步或用户明确要求时进行。

1. 记录正常连接、监听、规则与成功代理的正向对照。
2. 授权范围内短时模拟断开/入口故障/重连，系统阻断保持启用。
3. 对照物理出站包、请求结果和阻断计数；区分 TUN 与物理来源。
4. 恢复原节点、验证代理恢复。抓包丢包、无正向对照或恢复失败不能判定通过。
5. 按 IPv4/IPv6、具体目标和场景分别报告；没有全球 IPv6 上联就写未实测。

## iPhone 与 Tailscale

独立 VPN App 会竞争 iPhone 的 VPN 通道。支持内置 Tailscale 的 Shadowrocket 版本可在同一隧道内处理代理和 tailnet 流量。

- 先检查当前内置设置，不假设需要重填密钥。只访问私网时，Tailscale 出口节点留空，不同时启动独立 Tailscale VPN。
- 「已连接」、设备在线和服务实际可访问不同。Mac/Muse 应以准确服务地址发新请求验证，不用已缓存页面作证。
- macOS PF 不保护 iPhone；手机 VPN 开关不代表同等系统级断线保护。

## 同步助手崩溃

另有 Swift/AppKit 助手且实际崩溃栈为 `objc_retain → window getter → applicationShouldHandleReopen` 时，核对窗口生命周期：程序创建且需关闭后重开的窗口应保留强引用，设置 `isReleasedWhenClosed = false`，保持 delegate 存活。

修复真实代码时重建、签名实际安装 App 并验证相关生命周期。仅维护分流配置不需要重建任何 App。窗口捕获错误不等于这一崩溃。

## 来源

- [Shadowrocket DNS 与配置说明](https://github.com/LOWERTOP/Shadowrocket/wiki)（社区维护的实现用法参考；执行前核对版本）
- [APNIC 地址分配统计](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest)
- [Tailscale 与其他 VPN 共存限制](https://tailscale.com/docs/reference/faq/other-vpns)
- [Apple NSWindow.isReleasedWhenClosed](https://developer.apple.com/documentation/appkit/nswindow/isreleasedwhenclosed)
