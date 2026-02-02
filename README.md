# sing-box 全功能管理脚本

一套功能完整的 sing-box 节点管理和中转配置脚本，支持多种协议和高级中转功能。

## 💯 本项目顺利落地，特别鸣谢两家提供机器（本排名不分先后顺序）

<div align="center">

<table>
  <tr>
    </td>
    <td align="center" width="220">
      <a href="https://incudal.com/" target="_blank">
        <img src="https://incudal.com/incudal_logo.webp" width="100" alt="Incudal" />
        <br><sub><b>Incudal</b></sub>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://lazycats.vip/" target="_blank">
        <img src="https://lazycats.online/upload/logo2.png" width="100" alt="懒猫云" />
        <br><sub><b>懒猫云</b></sub>
      </a>
    </td>
  </tr>
</table>

</div>

## ✨ 特性

### 主脚本 (singbox.sh)

- 🚀 **一键安装** - 自动检测系统环境（systemd/OpenRC），自动安装依赖
- 📦 **多协议支持** - 支持 9 种代理协议以及 Argo 临时隧道和固定隧道节点的部署
- 🦘 **端口跳跃** - 支持 LXC/NAT 环境下的 Hysteria2 端口跳跃（应用层多端口监听）
- ⚡ **批量创建** - 智能批量部署，支持自定义 SNI 和端口冲突检测
- 🔗 **第三方节点导入** - 导入并适配第三方节点为本地监听
- 🔄 **智能管理** - 列表自动隐藏辅助节点，支持级联删除
- 🌐 **IPv6 完美支持** - 自动处理 IPv6 地址格式
- 🎯 **自定义名称** - 所有节点支持自定义命名

### 进阶脚本 (advanced_relay.sh)

- 🔀 **中转配置** - 支持落地机/中转机完整配置流程
- 🎫 **Token 机制** - 安全的落地节点 Token 生成与导入
- 🛠️ **端口修改** - 在线修改中转端口，无需重建
- 🗑️ **完整清理** - 删除中转时自动清理所有相关配置
- 📊 **可视化管理** - 查看所有中转路由和落地节点

---

## 📋 支持的协议

| 协议 | 节点添加 | 第三方导入 | 中转支持 |
|------|---------|-----------|---------|
| VLESS-Reality | ✅ | ✅ | ✅ |
| VLESS-WS-TLS | ✅ | ❌ | ❌ |
| AnyTLS | ✅ | ❌ | ✅ |
| Trojan-WS-TLS | ✅ | ❌ | ❌ |
| Hysteria2 | ✅ | ✅ | ✅ |
| TUICv5 | ✅ | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ | ✅ |
| VLESS-TCP | ✅ | ❌ | ✅ |
| SOCKS5 | ✅ | ❌ | ❌ |

---

## 🔧 系统要求

### 支持的系统
- Debian/Ubuntu (systemd)
- Alpine Linux (OpenRC)

---

## 📥 安装

### 交互式安装（推荐）

进入交互菜单手动配置节点：

```
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```

**快捷命令：sb**

### 快速部署

一条命令自动部署 VLESS-Reality、Hysteria2、TUICv5 三节点，适用于实例初始化：

```
(curl -sSL https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -qO /usr/local/bin/sb https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh) && chmod +x /usr/local/bin/sb && sb -q
```

**特点**：
- ✅ 端口随机分配
- ✅ SNI 默认使用 www.apple.com
- ✅ 自动输出节点链接和 Base64 订阅
- ✅ SSH 登录时自动显示节点信息
- ✅ 部署后可运行 `sb` 进入管理菜单

---

## 📖 使用指南

### 主脚本 (singbox.sh)

#### 基本操作

**主菜单选项：**
1. **添加节点** - 添加各种协议节点
2. **Argo 隧道节点** - 添加Argo 临时隧道节点
3. **查看节点分享链接** - 查看所有节点及其分享链接
4. **删除节点** - 删除指定节点
5. **修改节点端口** - 修改节点监听端口
6. **导入第三方节点** - 导入并适配第三方节点链接
7. **重启 sing-box** - 重启服务
8. **停止 sing-box** - 停止服务
9. **查看运行状态** - 查看服务状态
10. **查看实时日志** - 查看 sing-box 日志
11. **定时重启设置** - 设置每天自动重启 sing-box（显示服务器时区与北京时间时差）
12. **检查配置文件** - 验证配置文件语法
13. **更新脚本** - 更新管理脚本
14. **更新 Sing-box 核心** - 更新 sing-box 程序
15. **卸载** - 完全卸载 sing-box
16. **进阶功能** - 进入中转配置

#### 导入第三方节点

```
1. 选择"导入第三方节点"
2. 粘贴第三方节点链接
3. 选择本地适配协议（推荐 VLESS-TCP）
4. 设置本地监听端口
5. 自定义适配层名称（可选）
6. 自动创建本地适配层
```

**支持导入的第三方节点链接：**
```
- VLESS (Vision+REALITY)
- Hysteria2
- TUICv5
- Shadowsocks
```

---

### 进阶脚本 (advanced_relay.sh)

#### 中转配置流程

**场景：** 落地机（有节点）→ 中转机（中转流量）→ 客户端

#### 1. 落地机配置

```
# 选择"进阶功能" → "落地机配置"
# 选择要中转的节点
# 生成 Token（Base64 编码）
# 复制 Token 到中转机
```

**支持的落地节点：**
- VLESS-TCP（第三方适配层）
- Shadowsocks（第三方适配层）
- 本地创建的节点

> 第三方适配层的 Token 会自动使用 `127.0.0.1`

#### 2. 中转机配置

```
# 选择"进阶功能" → "中转机配置"
# 选择中转协议（VLESS-Reality/Hysteria2/TUIC）
# 粘贴落地机 Token
# 设置监听端口
# 设置伪装域名/SNI
# 输入节点名称
# 生成中转节点分享链接
```

#### 3. 查看中转路由

```
# 进阶功能 → 查看中转路由
# 显示所有中转入口→落地出口的映射
# 显示节点名称和端口信息
```

#### 4. 修改中转端口

```
# 进阶功能 → 修改中转路由端口
# 选择要修改的中转路由
# 输入新端口
# 自动更新配置、证书和链接
```

#### 5. 删除中转路由

```
# 进阶功能 → 删除中转路由
# 选择要删除的中转路由
# 自动清理：inbound、outbound、route、证书、YAML
```

---

## 🌐 IPv6 支持

脚本完美支持 IPv6 地址：

### 自动处理
- **YAML 配置**: IPv6 原始格式 (`2001:db8::1`)
- **节点链接**: IPv6 括号格式 (`[2001:db8::1]`)

### 兼容性
- ✅ v2rayN
- ✅ Clash
- ✅ Shadowrocket
- ✅ 所有标准客户端


---

## 📖 更新日志

### 2025.12.14
- **更新加入AnyTLS协议，同时支持AnyTLS作为中转入口协议的支持**
- **修复了一个BUG：生成落地Token时使用搭建节点协议时的IP，不再重新获取**

### 2026.01.09
- **对VLESS-WS-TLS和Trojan-WS-TLS节点协议新增了自签证书的搭建，不需要上传域名证书，默认会跳过证书验证，适合快速搭建优选回源节点，具体操作方法相同，都需要去CF绑定域名指向IP**
- **新增了Argo临时隧道节点的搭建，目前通过128M内存的Debian和Alpine系统测试，能实现singbox和Argo同时运行，仅为测试场景，实际使用预计占用会更高，尽量不要在≤128M内存的机器上使用Argo隧道。**

### 2026.01.13
- **增加 Hysteria2 端口跳跃功能**：引入应用层多端口监听模式，彻底解决 LXC/NAT 机器无法使用端口跳跃的问题，同时保留对大端口段的 iptables 支持。
- **优化主脚本&子脚本**：优化交互流程和界面。

### 2026.01.19
- **加入定时重启功能**：自动获取服务器当前时间和时区，并显示与北京时间的时差，方便设置定时重启，适合一些需要定时重启singbox的用户
- **加入快速部署三节点模式**：快速部署三节点适合给一些实例的初始化、新开实例、重装实例使用，会自动部署本脚本，并在SSH登录的时候自动显示三节点的节点链接，端口为随机端口（NAT机器需要自行映射端口）

### 2026.01.25
- **新增Argo固定隧道**：新加入Argo固定隧道的部署，由于CF在创建固定隧道的时候，所跟随出现的token是显示不完全的，通常需要复制后进行token提取。新增的Argo固定隧道则不需要提取，只需要完整复制粘贴CF创建固定隧道时所给出的任意带有Token的命令即可（不管是Windows或者是debian等），脚本会自动识别隧道Token并自动填入。关于如何创建固定隧道节点，需要自行YouTuBe搜索，部署搭建方式都大同小异。

### 2026.01.27
- **优化内存回收机制**：优化了跑测速时会出现singbox进程被杀死，目前测试下来内存回收机制还算不错，起码能够顺利跑完测速。
- **hy2节点协议优化**：hy2节点协议不再需要手动输入上下行的限制，目前写死了10Gbps（也就是10000M），会自动根据机器的带宽进行调整。
- **AnyTLS协议优化**：优化了AnyTLS协议的填充机制，保证AnyTLS协议的强伪装前提下，降低了不少延迟，提高了不少速度。

### 2026.02.02
- **节点部署优化**：新增节点部署成功后自动显示节点链接，单节点部署的时候则无需返回主菜单查看节点链接了。
- **SS节点协议增强**：新增了一个2022-blake3-aes-128-gcm+Padding(数据填充)的部署。
- **默认伪装域名变更**：由之前的微软域名变更为苹果域名，虽然这两个域名都是很多人在用的，综合下来发现苹果域名要比较实用一些。








