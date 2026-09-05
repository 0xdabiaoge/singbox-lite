# sing-box + Xray 多协议管理脚本

一套面向 Linux 服务器的 sing-box + Xray 双核心管理脚本，提供节点创建、服务管理、落地/中转、第三方节点导入、端口转发、Argo 隧道和 Clash/Mihomo 配置输出。

当前文档按以下脚本版本整理：`singbox.sh v28`、`advanced_relay.sh v19`、`xray_manager.sh v3.1.3`。

> 脚本需要 root 权限。请仅在拥有管理权或明确授权的服务器和网络中使用。

## 项目组成

| 文件 | 作用 |
| --- | --- |
| `singbox.sh` | 主入口；负责依赖、sing-box、节点、Argo、DNS、服务和子脚本调度 |
| `advanced_relay.sh` | 落地/中转、第三方节点导入、端口转发和规则管理 |
| `parser.sh` | 第三方节点链接的严格解析器，通常由中转脚本调用 |
| `xray_manager.sh` | Xray-core 安装、服务和节点管理，与主脚本共享 `clash.yaml` |

## 主要能力

- sing-box 与 Xray 双核心可独立安装、更新和运行。
- 节点创建、查看、删除、端口修改、批量创建和分享链接输出。
- VLESS、Trojan、Hysteria2、TUIC、AnyTLS、Shadowsocks、SOCKS5 等协议管理。
- VLESS-WS / Trojan-WS 的 Argo 临时隧道和固定隧道。
- 支持本机节点 Token 与第三方落地节点两种接入流程，并可选择四种中转入口协议。
- nftables 内核转发与 sing-box 用户态转发双引擎，按实际权限自动选择。
- IPv4/IPv6 地址、域名目标、TCP、UDP、TCP+UDP 端口转发。
- 共享状态锁、原子写入、事务快照和失败回滚，降低跨脚本并发修改造成的配置损坏风险。
- 对配置、元数据、私钥、Token 和临时文件采用收紧的权限与清理策略。

## 系统与环境

### 重点支持

- Debian / Ubuntu：systemd
- Alpine Linux：OpenRC
- 无 systemd/OpenRC 的精简环境：使用 direct 后台模式
- CPU：`x86_64/amd64`、`aarch64/arm64`、`armv7l`

脚本也包含 `yum`/`dnf` 依赖安装路径；主要适配系统为 Debian、Ubuntu 和 Alpine。

### 虚拟化与容器

- KVM、具备 `NET_ADMIN` 的 LXC：优先使用 nftables。
- 无特权 LXC、Docker、Podman：nftables 探测失败时自动降级为 sing-box 用户态转发。
- Docker/Podman 如果不是 host 网络，必须在宿主机预先发布对应的 TCP/UDP 端口；容器内创建监听并不等于宿主机端口已经开放。
- 128 MB Podman Alpine/Debian 的核心安装路径已做低内存优化；sing-box 与 Xray 会按物理内存及 cgroup 上限设置 Go 运行时软内存限制，128 MB 档约为 `40MiB`。实际可用内存仍受宿主机、页缓存和同时运行的服务影响。

## 安装与启动

```bash
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```

以后直接运行：

```bash
sb
```

首次启动会安装基础依赖并初始化状态文件，但不会强制同时安装两个核心。请按需要使用主菜单 `[15]` 安装/更新 sing-box，使用 `[16]` 安装/更新 Xray。

`[15]` 进入后可选择：

1. 安装/更新 sing-box 最新稳定版。
2. 安装固定版 `1.13.21`。安装成功后会写入持久版本锁，后续不能再通过脚本升级核心，只能重新安装同一固定版本。

固定版锁定状态会显示在主菜单的 sing-box 版本旁。固定版和最新版都会校验官方发布标签、资产名称、SHA-256 摘要、二进制实际版本以及现有 `config.json + relay.json` 组合配置；任一步失败都不会提交新核心。

子脚本缺失时，主脚本会从同一仓库下载，并在覆盖或执行前检查 HTTPS 来源、非空内容、Bash shebang 和语法。

## 主菜单

| 分类 | 编号 | 功能 |
| --- | ---: | --- |
| 节点管理 | 1 | 添加 sing-box 节点 |
|  | 2 | Argo 隧道节点 |
|  | 3 | 查看节点链接 |
|  | 4 | 删除节点 |
|  | 5 | 修改节点（名称、地址、端口、认证、SNI/证书及协议专属参数） |
| 服务控制 | 6 | 重启 sing-box |
|  | 7 | 停止 sing-box |
|  | 8 | 查看运行状态 |
|  | 9 | 查看实时日志 |
|  | 10 | 定时重启设置 |
|  | 11 | 时间诊断、核心时间补偿及有权限环境的系统校时 |
| 配置与更新 | 12 | 检查配置文件 |
|  | 13 | 更新脚本 |
|  | 14 | DNS 设置 |
| 核心管理 | 15 | 安装/更新 sing-box 核心 |
|  | 16 | 安装/更新 Xray 核心 |
|  | 17 | 卸载脚本 |
| 进阶功能 | 18 | 落地/中转/第三方节点导入/端口转发 |
|  | 19 | Xray 节点管理 |
| 退出 | 0 | 退出脚本 |

`[5] 修改节点` 会按实际协议显示可用项目。所有主节点均可修改名称、客户端连接地址、端口和认证信息；Reality 可更新伪装域名并轮换密钥，TLS 类节点可更新 SNI、自签证书或自定义证书，WebSocket/gRPC 可修改传输路径，Hysteria2 还可调整混淆、端口跳跃和客户端带宽。保存时会统一校验 sing-box 配置并同步元数据、分享链接与 Clash/Mihomo 配置，失败则自动回滚。

## sing-box 节点协议

| 菜单 | 协议 | 说明 |
| ---: | --- | --- |
| 1 | VLESS + TCP + Reality + Vision | `type=tcp`、`security=reality`、`flow=xtls-rprx-vision` |
| 2 | VLESS + WebSocket + TLS | 支持自签名或自备证书，可输出直连/CF 场景配置 |
| 3 | Trojan + WebSocket + TLS | 支持自签名或自备证书，可输出直连/CF 场景配置 |
| 4 | VLESS + gRPC + TLS | 支持 gRPC TLS 节点创建 |
| 5 | AnyTLS / Any-Reality | 可单独创建或同时创建；Any-Reality 不写入 Mihomo `clash.yaml` |
| 6 | Hysteria2 | 支持 Salamander 混淆和端口跳跃 |
| 7 | TUIC v5 | 使用 QUIC/UDP |
| 8 | Shadowsocks | 经典 SS、SS2022、Padding、SS2022 + ShadowTLS v3 |
| 9 | 纯 VLESS + TCP | 无 TLS/Reality，适合明确知道风险和使用场景的用户 |
| 10 | SOCKS5 | 本机创建的是用户名/密码认证节点 |
| 11 | 批量创建 | 支持多协议组合、端口规划、冲突检查和整批回滚 |

sing-box Shadowsocks 可选项：

- `aes-128-gcm`
- `aes-256-gcm`
- `chacha20-ietf-poly1305`
- `xchacha20-ietf-poly1305`
- `2022-blake3-aes-128-gcm`
- `2022-blake3-aes-256-gcm`
- `2022-blake3-chacha20-poly1305`
- `2022-blake3-aes-256-gcm` + Multiplex/Padding
- `2022-blake3-aes-256-gcm` + ShadowTLS v3

SS2022 会按算法生成严格长度的 Base64 密钥：AES-128 使用 16 字节，AES-256 与 ChaCha20 使用 32 字节。批量创建支持前述七种纯 SS 加密方式及 Padding 组合。

ShadowTLS 组合没有通用的单行分享链接，脚本会给出 Mihomo 配置参考，并把完整配置写入 `clash.yaml`。

## 第三方节点导入

入口：主菜单 `[18]` → 进阶转发菜单 `[3]`。

第三方导入采用“先选协议、再输入对应信息”的严格模式，不会猜测协议或静默降级传输方式。

| 选项 | 支持方式 | 约束 |
| --- | --- | --- |
| VLESS + TCP + Reality + Vision | `vless://` 链接 | 必须是原生 TCP、Reality、`xtls-rprx-vision` |
| 纯 VLESS + TCP | `vless://` 链接 | 必须是原生 TCP，不能启用 TLS/Reality |
| Shadowsocks `aes-128-gcm` | `ss://` 链接 | 不接受插件或其他加密方法 |
| Shadowsocks `aes-256-gcm` | `ss://` 链接 | 不接受插件或其他加密方法 |
| SOCKS5 无认证 | 手动输入 | 输入服务器地址和端口 |
| SOCKS5 用户名/密码认证 | 手动输入 | 输入服务器地址、端口、用户名和密码 |

Hysteria2、TUIC、VMess、Trojan、AnyTLS 等第三方分享链接不属于当前导入白名单；解析器会明确拒绝，而不是生成可能错误的配置。

VLESS 两种导入结果都会显式写入 `network: "tcp"`。Reality 模式还会严格检查 SNI、公钥、Short ID、uTLS 指纹和 `flow`。

## 落地与中转

### 方式一：本机节点 Token

1. 在落地机进入主菜单 `[18]` → `[1]`，选择可导出的本机节点。
2. 脚本生成 `ENC2` 加密 Token 和独立解密口令。
3. 使用不同渠道传递 Token 与口令。
4. 在中转机进入 `[18]` → `[2]`，导入 Token 并输入口令。
5. 选择中转入口协议、监听端口、SNI 和节点名称。

新版 Token 使用 AES-256-CBC + PBKDF2，并把密文与口令分开显示。旧版 `ENC` 和 Base64 Token 仍可兼容导入，但会给出安全警告。

当前文档化的 Token 兼容范围是：原生 TCP/Reality/WS 类型的 VLESS、Trojan-WS、经典 Shadowsocks、Hysteria2、TUIC 和 AnyTLS。SS2022 会从 Token 列表中隐藏；VLESS gRPC、Any-Reality、ShadowTLS 组合和 SOCKS5 不应视为已保证的 Token 导出类型。

### 方式二：第三方落地节点

1. 在中转机进入 `[18]` → `[3]`。
2. 选择第三方节点类型并输入链接或 SOCKS5 信息。
3. 解析器和中转脚本执行双重 schema 校验。
4. 选择本机中转入口协议。
5. 脚本创建入口、落地 outbound、路由、分享链接和客户端配置。

可选中转入口：

- VLESS + TCP + Reality + Vision
- Hysteria2
- TUIC v5
- AnyTLS

创建、删除和修改中转路由都使用事务快照；配置检查或服务重启失败时会尝试恢复原状态。

## 端口转发

入口：主菜单 `[18]` → 进阶转发菜单 `[8]`。

### 自动选择引擎

脚本不是只根据“LXC/KVM/Podman”名称做判断，而是实际尝试创建并删除一条 nftables 测试规则：

- 探测成功：使用 nftables DNAT 内核转发。
- 探测失败或缺少权限：使用 sing-box `direct` 用户态转发。

因此，具备权限的 LXC 和 KVM 可以使用 nftables；常见的无特权 Docker/Podman 会自动降级为 sing-box。规则创建后也可以在菜单中手动切换引擎，切换失败会恢复旧规则。

### 支持能力

- TCP、UDP、TCP+UDP
- IPv4、IPv6、域名目标
- 规则命名、查看、修改、删除、清空
- 主配置、中转配置、Xray、端口转发和 Hysteria2 跳跃范围的冲突检查
- nftables 域名目标每 1 分钟检查一次解析结果并更新规则
- nftables 规则写入独立的 `inet singboxlite` 表，减少对系统其他防火墙规则的干扰

sing-box 用户态 UDP 转发的性能通常低于 nftables，但适合没有 netfilter 权限的容器环境。

## Xray 节点管理

主菜单 `[19]` 进入 Xray 管理；`[16]` 只负责安装/更新 Xray 核心。

| 添加菜单 | Xray 协议 | 客户端提示 |
| ---: | --- | --- |
| 1 | VLESS + TCP + Reality + Vision | 客户端需支持 Reality/Vision |
| 2 | VLESS + gRPC + Reality | 客户端需支持 gRPC Reality |
| 3 | Trojan + XHTTP + Reality | Mihomo/Clash 不支持 XHTTP |
| 4 | Trojan + gRPC + Reality | 客户端需支持 gRPC Reality |
| 5 | VLESS + XHTTP + TLS | 面向 Xray 客户端；可用于 CF H2 回源 |
| 6 | VLESS + gRPC + TLS | 使用 CF 时需开启 gRPC 并正确配置 SSL 模式 |
| 7 | Trojan + gRPC + TLS | 使用 CF 时需开启 gRPC 并正确配置 SSL 模式 |
| 8 | Shadowsocks | AES-128/256-GCM、ChaCha20、XChaCha20、三种 SS2022 及 SS2022 + Padding |

Xray 与 sing-box 使用独立的服务和 JSON 配置，但共享 `/usr/local/etc/sing-box/clash.yaml`。删除和修改节点时只处理归属于目标节点的 YAML 项，避免误删另一核心的同名或相邻配置。

## IPv6

- sing-box 和 Xray 入站默认使用 `::` 监听；是否同时接受 IPv4 取决于系统的双栈设置。
- YAML 中保留 IPv6 原始地址，分享链接中的 IPv6 使用 `[地址]` 格式。
- 端口转发可识别 IPv4/IPv6 字面量和域名解析结果。
- 最终可用性仍取决于 VPS 路由、防火墙、容器端口发布、客户端和具体协议实现；不再承诺“所有客户端完美兼容”。

## 配置与数据位置

| 路径 | 内容 |
| --- | --- |
| `/usr/local/bin/sb` | 主脚本快捷命令 |
| `/usr/local/bin/sing-box` | sing-box 核心 |
| `/usr/local/bin/xray` | Xray 核心 |
| `/usr/local/etc/sing-box/config.json` | sing-box 主节点配置 |
| `/usr/local/etc/sing-box/relay.json` | 中转和用户态端口转发配置 |
| `/usr/local/etc/sing-box/clash.yaml` | sing-box/Xray 共享客户端配置 |
| `/usr/local/etc/sing-box/metadata.json` | 主节点元数据和分享链接 |
| `/usr/local/etc/sing-box/core-version.lock` | 固定版 `1.13.21` 的持久升级锁 |
| `/usr/local/etc/sing-box/relay.d/` | 中转、端口转发和辅助状态 |
| `/usr/local/etc/xray/config.json` | Xray 服务端配置 |
| `/var/log/sing-box.log` | sing-box 日志 |
| `/var/log/singbox_argo.log` | Argo 日志 |

状态文件可能包含 UUID、密码、私钥和分享链接，请不要公开上传服务器上的配置目录。

## 安全与可靠性机制

- sing-box 使用每分钟一次的进程内 NTP 时间补偿，不要求 LXC/Podman 修改系统时间；启动前有界探测备用时间源，只迁移脚本管理的默认项并保留用户自定义设置。所有默认时间源不可达时会暂缓启用补偿并告警，下次启动/重启或 `[11]` 修复时重新探测，不把服务运行当作 SS2022 可用证明。
- `[11]` 区分时间诊断、核心补偿修复和系统校时；容器不执行系统校时，不新增常驻校时程序。Xray 仍依赖系统时间，不继承 sing-box 的补偿，创建 SS2022 时会明确提示。SS2022 始终保留 30 秒时间窗口，客户端也需时间准确。
- 所有脚本共享同一把状态锁，避免主脚本、中转脚本和 Xray 脚本并发写配置。
- JSON/YAML 使用同目录临时文件、格式校验和原子替换。
- 节点创建、删除、端口修改和核心更新在关键失败时执行回滚。
- sing-box、Xray 和 yq 下载执行来源约束、SHA-256 校验和可执行性检查。
- 新核心替换前后会检查版本；已有配置存在时还会执行组合配置校验。
- 敏感配置默认按 root-only 权限保存，临时文件和运行目录会限制权限并清理。
- 自签 TLS 分享链接在可取得证书指纹时只输出 `pcs` 固定证书，不再同时输出新版 Xray 已拒绝的 `insecure` 参数。
- 第三方解析器只输出最小允许 schema，中转脚本会再次校验字段和值。

## 更新日志

以下记录保留项目历次主要修改。早期条目描述的是当时实现；如果与当前功能不同，应以前文的当前支持范围为准。

### 2025.12.14

- 新增 AnyTLS 节点及 AnyTLS 中转入口；修复生成落地 Token 时重新获取 IP，改为保留节点创建时使用的地址。

### 2026.01.09

- VLESS-WS-TLS、Trojan-WS-TLS 新增自签证书部署；加入 Argo 临时隧道，并针对 128 MB Debian/Alpine 做初步低内存适配。

### 2026.01.13

- 加入 Hysteria2 端口跳跃和应用层多端口监听，改善 LXC/NAT 环境兼容性；同步优化主脚本与子脚本交互。

### 2026.01.19

- 加入定时重启和时区提示；曾加入快速三节点部署，后续已于 2026.03.08 移除。

### 2026.01.25

- 加入 Argo 固定隧道，可直接从 Cloudflare 提供的 Windows/Linux 命令中提取完整 Tunnel Token。

### 2026.01.27

- 优化测速时的内存回收，降低 sing-box 被杀死的概率；简化 Hysteria2 带宽参数；调整 AnyTLS Padding 以兼顾伪装和性能。

### 2026.02.02

- 节点创建成功后直接显示分享链接；当时新增 SS2022 AES-128-GCM + Padding；默认伪装域名由微软域名调整为苹果域名。

### 2026.02.06

- 项目拆分为 `singbox.sh`、`advanced_relay.sh`、`parser.sh`；扩展落地 Token 和第三方节点中转流程；主菜单加入 Argo 状态，Argo 端口支持自定义。

### 2026.02.15

- 完成主脚本、中转脚本和解析器的进一步重构；加入批量节点部署、端口数量计算、连续端口输入及冲突检查。

### 2026.02.21

- 新增 `xray_manager.sh` 和 Xray-core 双核心管理，支持 8 种 Xray 节点；主菜单加入 Xray 状态；增加 XHTTP/gRPC TLS 等 Cloudflare 回源协议。

### 2026.02.24

- 中转脚本加入 sing-box 用户态端口转发；修复第三方域名节点因默认 DNS 选择造成的连通问题，解析 DNS 改用 Cloudflare。

### 2026.03.01

- 适配 sing-box 1.13 DNS 结构并保留逃生环境变量；Alpine 改用 musl 核心；显示 sing-box/Xray 版本；端口转发规则支持命名。

### 2026.03.04

- 修复 Hysteria2 端口跳跃和中转仅监听 IPv4 的问题；sing-box/Xray 统一补充经典 SS、SS2022、Padding 及 Base64 分享链接处理。

### 2026.03.08

- 移除快速三节点部署；核心改为按需手动安装；修复 Argo 隧道小概率未触发进程守护的问题。

### 2026.03.24

- 当时加入 LXC/KVM 环境识别：LXC 使用 sing-box TCP 转发，KVM 使用 iptables TCP+UDP 转发；同时精简交互流程。该引擎策略后续已被 nftables 能力探测替代。

### 2026.04.07

- iptables 转发加入域名目标和定时解析刷新；新增 SS2022 + ShadowTLS v3 组合，并通过 `clash.yaml` 提供客户端配置。

### 2026.04.26

- 完善当时的 iptables 内核转发与 sing-box 用户态转发组合；修复 LXC 环境的 Hysteria2 端口跳跃遗留问题。

### 2026.05.04

- 优化 Docker/Podman Alpine、Debian 安装流程和低内存解压；简化 sing-box/Xray 安装流程；将时间同步拆分为主菜单独立功能。

### 2026.05.24

- 依赖改为首次安装和缺失时检查，减少重复执行包管理器；AnyTLS 增加 Any-Reality 创建选项。

### 2026.05.29

- 端口转发由 iptables 迁移到 nftables；受限 Podman 容器继续使用 sing-box 用户态转发；补充主节点、中转和 Hysteria2 跳跃范围的端口冲突检查。

### 2026.06.11

- Argo 加入 Early Data；sing-box 新增 VLESS + gRPC + TLS；TLS 节点链接加入自签证书 SHA-256 指纹，并分别输出直连与 Cloudflare 场景链接。

### 2026.07.27

- 连接日志加入自动清理，避免小磁盘机器日志占满空间；主菜单加入 sing-box DNS 设置。

### 2026.08

- 增加跨脚本共享锁、原子 JSON/YAML 写入、事务快照和失败回滚；修复 Xray 双栈监听迁移、YAML 精确删除和端口联动更新。
- 加固核心与工具下载校验、候选配置检查、旧核心回滚，以及 PID、日志、证书、Token、元数据、临时文件和运行目录权限。
- 完善主节点、中转、Xray、端口转发和 Hysteria2 跳跃范围之间的冲突识别；nftables 域名目标刷新调整为每分钟执行并支持 IPv4/IPv6。

### 2026.08.31

- 修复 128 MB Podman Alpine 安装 sing-box 时可能被 OOM Kill：跳过容器中无效的可选依赖，改为流式下载、校验和解压，并清理中断安装的临时目录。
- 端口转发改为实际写入测试规则的 nftables 能力探测：LXC/KVM 有权限时使用 nftables，Podman 等受限容器自动降级为 sing-box 用户态转发。

### 2026.09.01

- sing-box 与中转入口统一明确为 `VLESS + TCP + Reality + Vision`，并保留旧内部标签以兼容已有节点。
- 第三方导入收敛为 VLESS Reality Vision、纯 VLESS TCP、SS AES-128/256-GCM 四个链接选项，以及无认证/带认证两类手动 SOCKS5。
- VLESS 解析结果显式写入 `network: "tcp"`；中转 schema 同步拒绝缺少 network、非 TCP 传输及不符合所选类型的节点。

### 2026.09.03

- sing-box 核心安装加入二级选择：可跟随最新稳定版，或安装并永久锁定 `1.13.21` 固定版；锁定后拒绝后续核心升级。
- 固定版与最新版统一校验官方发布状态、精确资产名称、SHA-256 和二进制实际版本，并继续保留组合配置检查、服务启动验证及失败回滚。
- 按 sing-box 1.14 移除项复核配置：保留 1.12+ typed DNS 和 `default_domain_resolver`，清理已失效的旧版 DNS 兼容环境变量。

### 2026.09.04

- 修复 sing-box 1.14 在部分 Linux/systemd-resolved 环境中使用 local DNS 时查询可能阻塞 10 秒的问题；新配置默认启用 `prefer_go`，旧配置启动时自动迁移并保留原 DNS 地址与解析策略。
- 继续收紧 128 MB 容器安装路径：Debian 依赖改为逐包、无 recommends、无 dpkg PTY 安装；Podman 默认配置不再启用容易因 UDP 123 受限而阻塞启动的 NTP。
- 修复服务启动继承共享锁文件描述符、systemd 失败状态未清理，以及 Argo 临时节点空字段错位导致名称和凭据元数据串位的问题。
- Argo 临时隧道改为结合系统解析与 Cloudflare DoH 确认域名已经完成 DNS 发布后才提交；首个域名未发布时会清理并自动重试一次，避免本机负缓存误判或生成表面成功但无法解析的节点。
- 修复主卸载先删元数据后停 Argo、遗留 sing-box/Xray 服务与定时器、以及误删用户 MOTD 分隔行的问题；卸载现在按进程、规则、服务、状态的依赖顺序清理。
- 批量创建进一步校验单一端口范围和 Shadowsocks 选项，避免畸形范围或 Shell 通配符参与拆词；任何非法输入都会在写配置前拒绝。
- 管理脚本更新改为四个组件全部预下载、校验后再统一提交；任一组件失败会保持整组旧文件，并拒绝把较新的本地版本自动降级。
- 修复 Alpine/BusyBox 下 Xray 原子 JSON 临时文件模板不兼容；自签 TLS 链接优先使用证书指纹，兼容已移除 `allowInsecure` 的新版 Xray。
- 修复 Podman 低内存安装跳过 `cron` 后 Argo 节点缺少自动守护的问题：仅在使用 Argo 时按需安装并启动 cron；守护创建失败会回滚节点，避免留下无法自愈的半成品配置。
- sing-box 与 Xray 统一加入基于物理内存、cgroup `memory.max`/`memory.high` 的 `GOMEMLIMIT`；128 MB 档由 `48MiB` 收紧到约 `40MiB`，并覆盖 systemd、OpenRC、direct 三种启动方式。

### 2026.09.05

- 修复 SS2022 在漂移时钟及容器中的时间补偿策略：默认 NTP 从 `30m` 调整为 `1m`，取消按 Podman 名称删除默认 NTP，加入有界探测与备用源、旧默认配置迁移、自定义配置保护及时间诊断；系统校时不再在容器中尝试修改宿主机时间。
- 修复 DDNS 端口转发在 cron 精简环境下找不到 `nft`、导致域名 IP 已变化但规则未同步的问题；已有定时任务更新脚本后即可生效，并补充解析、规则更新、回滚与持久化失败日志及失败退出状态。
- sing-box 与 Xray 的 Shadowsocks 创建菜单统一补齐 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305` 和三种 SS2022 加密方式，并保留原有 Padding、ShadowTLS 组合。
- SS2022 改为按算法生成严格长度的 Base64 密钥：AES-128 使用 16 字节，AES-256 与 ChaCha20 使用 32 字节；sing-box 批量创建同步支持七种纯 SS 加密方式。
- sing-box `[5] 修改节点` 在重新生成 Shadowsocks 认证信息时复用相同的密钥规则，并同步更新服务端配置、元数据、分享链接与 Clash/Mihomo 配置。
