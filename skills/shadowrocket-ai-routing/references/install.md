# 在另一台 Mac 安装（2.0.0）

## 范围与首次授权

本版本附带可构建的沙盒节点同步 App、动态识别/安装 CLI、独立系统 PF 守护服务、配置合并器及有限故障验证器。支持 macOS 13+，构建产物含 Apple Silicon 与 Intel 架构；本次只在开发机器上执行了 App 自检，没有在另一台物理 Mac 或 Intel Mac 完成端到端安装实测。

两次必要授权不能省略：同步 App 的精确目录只读授权、安装系统规则的管理员授权。不得索要密码、复制认证密钥或自动扩大目录访问。安装时会清理本机旧的非回环连接状态，可能短暂打断现有连接；规则更新也可能使连接重建。

本例不自动安装第二套保护。发现旧 `ShadowrocketEgressGuard` 或自定义 PF 接入时拒绝安装，保留已有网络；需要单独审阅升级/集成，而非先卸载旧保护。

## 1. 准备组件

在目标 Mac 上运行。需要 Python 3.9+、Apple Command Line Tools（Swift、macOS SDK）和已安装的 Shadowrocket。先确认原代理已连接且出口正确。

可下载 GitHub Release 的 zip 并解压；内含 `apps/Shadowrocket Routing Node Sync.app`、Skill 和 CLI。发布 App 为 ad-hoc 签名，未公证，目标系统可能要求用户批准运行。不要关闭 Gatekeeper 或删除系统安全策略；也可在目标 Mac 从源码构建。

从源码构建时，在仓库根目录运行：

```sh
python3 tools/build_release.py
```

实际通用 App 位于 `dist/Shadowrocket Routing Node Sync.app`。不要把开发机已授权的 App 数据容器、节点快照或安装计划复制给另一台 Mac。

## 2. 安装只读助手

从源码构建的目录运行：

```sh
python3 skills/shadowrocket-ai-routing/scripts/portable_guard.py setup-helper --app 'dist/Shadowrocket Routing Node Sync.app'
```

使用 Release 解压目录时，将 `--app` 的参数改成 `'apps/Shadowrocket Routing Node Sync.app'`。

助手安装到当前用户的 Applications，LaunchAgent 保持运行。打开助手的「授权只读节点目录」，选择本机用户 Library/Group Containers 下的 **group.com.liguangming.Shadowrocket 本身**。父目录或子目录都会被拒绝。等待显示节点已读取。

助手没有网络权限、没有硬编码的绝对写入例外；输出位于自身沙盒容器的 Application Support，目录 0700、快照 0600。只输出主机、原端口/范围、支持的协议与匿名标签，不导出节点密码、UUID 或订阅链接。

支持的协议为 Trojan、VLESS、Hysteria2、Shadowsocks、Socks5；不支持的协议、结构不明或不完整来源会阻止放行更新。不同 Shadowrocket 版本的归档结构可能需要适配，不能保证所有未来版本自动识别。

## 3. 检查识别结果

```sh
python3 skills/shadowrocket-ai-routing/scripts/portable_guard.py discover --offline
```

该动作只读发现监听端口及助手/旧版保护是否存在，不查询外网、不操作 VPN、不修改 PF。省略 `--offline` 可检查实际 HTTP/SOCKS5 混合代理与当前出口。

识别依赖本机 packet-tunnel 进程、其登录 UID 和真实 loopback listener，不使用固定端口。VPN 服务标识和物理默认网卡也在生成计划时发现；多服务、多物理默认路由或多可用监听端口存在歧义时停止，不猜测；另有同时连接的 VPN 时要求先审阅共存，不默认放行任意中继或 UDP。

## 4. 合并并启用分流

通过 Shadowrocket 自身界面备份活动配置，导出或从文本编辑器获取配置到本机私有目录。不得直接以 root 修改应用私有数据文件。

在本机创建 private 目录（已有同名目录时先核对所有者与权限，不覆盖其内容）：

```sh
mkdir -m 700 private
```

将导出内容保存为仅当前用户可读的 `private/current.conf`，再运行：

```sh
python3 skills/shadowrocket-ai-routing/scripts/portable_guard.py merge-profile --input private/current.conf --output private/merged.conf
```

合并器只改 General 中相关 DNS/回退键和 Rule；保留监听端口、代理组、Hosts、重写及其他原有节。输出 0600，原文件不改。它不会自动将文件写入厂商数据目录。

由当前执行任务的代理通过 Shadowrocket UI 将合并结果应用到备份后的活动配置，保存、编译，确认仍使用原节点、原代理链以及「全局路由 → 配置」。现有订阅与选中出口不能因安装而被替换。CLI 的 `--profile-applied` 只是这一步完成后的显式确认，不能代替 UI 读回。

## 5. 生成安装计划

普通非 SOCKS5 入口可直接生成：

```sh
python3 skills/shadowrocket-ai-routing/scripts/portable_guard.py plan --output private/plan
```

自动读取本机助手快照，识别端口、VPN 服务与物理网卡。入口域名使用独立国内加密 DoH 启动解析，避免新节点未在白名单时无法查询自身；AI 地址与 APNIC 数据通过当前代理查询。AI 域名不能作为入口启动查询目标。文件为本机 0600/0700 私有数据，不要上传。

**代理链关系不能仅靠节点协议或名字猜测。** 如果清单有 Socks5 节点，先在 Shadowrocket「通过代理」读回它是否为 A→B 中的出口：

- 对已确认的链式出口，追加 `--chain-exit 实际主机`，可重复；它不会获得物理直连例外。
- 对已确认本来就是直接入口的 SOCKS5，追加 `--direct-socks5 实际主机`，可重复。
- 若不能确认，停止并请求这项信息；不要为追求自动化放行所有 SOCKS5。

主机应从本机读回，不复制示例或原机器地址。其他已支持协议的普通新增节点自动按原端口同步；新增未分类 SOCKS5、链式出口移除/改端口时保留旧规则，需要重新审阅。安装计划输出目录必须是新的，避免覆盖已审阅计划。

## 6. 管理员安装

在生成计划后的 30 分钟内，确认原出口仍正常，再运行单独一行：

```sh
sudo /usr/bin/python3 -I skills/shadowrocket-ai-routing/scripts/portable_guard.py install --plan private/plan/plan.json --profile-applied
```

只在用户自己的终端输入密码。安装器重新核对用户、端口、节点快照、VPN、默认网卡和出口；审查 PF 根规则与 hook 顺序、校验候选语法后安装本方案。歧义或冲突时拒绝，而非覆盖原系统规则。

安装位置：`/Library/Application Support/ShadowrocketRoutingGuard`；系统服务 `org.shadowrocket-routing.guard`；PF anchor `com.apple/000.shadowrocket-portable`。运行时文件和元数据 root 专属，服务以经过所有权检查的系统 Python 运行，不执行用户目录内的守护程序。

首次启用后显示「已安装」不等于故障验证通过。部分安装失败时先检查状态；维护动作不会自动放开直连。

## 7. 验证与后续更新

```sh
sudo /usr/bin/python3 -I '/Library/Application Support/ShadowrocketRoutingGuard/portable_guard.py' status
```

首次安装或改变 PF/代理链后，做一次必要故障验证：

```sh
sudo /usr/bin/python3 -I '/Library/Application Support/ShadowrocketRoutingGuard/portable_guard.py' verify --fault-test
```

测试暂时断开/重连 Shadowrocket，系统阻断始终启用；独立 watchdog 尝试恢复服务，最后核对原出口。验证器检查有限 AI/canary HTTPS 目标的 IPv4 物理出站、代理正向对照、国内物理直连与阻断计数。TUN/按需重连使证据不充分时报告未完成，不能把 0 抓包或虚拟来源直接判为通过。

此验证器没有注入 provider 崩溃，也没有完成真实 IPv6 故障验证；完整边界按报告说明。当前开发机保留旧保护，未用迁移组件重新断线安装，不会把旧报告当作新版安装结果。

守护程序约每 5 秒查看快照，约每 10 分钟刷新入口 DNS/AI，国内数据每日尝试刷新。更新失败保留上次有效规则；CN 数据超过 30 天时关闭国内物理例外并保留 AI 拒绝。出口 IP 的初始基线不自动改写。

仅修改国内域名/DNS且系统规则未改时，不必重跑故障测试；确认实际服务恢复和 AI 仍走代理即可。

## 回退

- 配置回退：在 Shadowrocket 中恢复本次备份，确认选中出口与端口；系统阻断仍保留。
- 同步失败：保留旧 PF，检查助手目录授权、完整性、快照时间或协议，不要通过卸载恢复连通。
- 仅当用户明确决定移除此保护时：

```sh
sudo /usr/bin/python3 -I '/Library/Application Support/ShadowrocketRoutingGuard/portable_guard.py' uninstall --remove-protection
```

卸载只停止本方案系统服务、移除本方案 anchor 规则和 load 指令、释放拥有的 PF 引用；不执行全局 PF disable。保留安装状态/备份及用户助手以供审阅，不自动恢复或覆盖订阅、活动配置和其他防火墙。
