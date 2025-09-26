## **SingBox 精简版**

## 适配标准版以及LXC、KVM等虚拟化的Debian/CentOS/Ubuntu和Alpine，同时支持Docker容器虚拟化的Debian、Alpine，仅在上述系统中测试使用。
## 重要提示：通过Docker容器虚拟化出来的系统有个小bug，重启机器后，需要重新进入脚本，重启一遍singbox，才能正常使用。

## **✨ 功能特性**
- **脚本风格：Gemini2.5Pro**
- **轻量高效：资源占用极低，适合小内存机器使用。**
- **自动识别IPV4，ipv6**
- **既有直连节点协议，也有落地节点协议**
- **Hysteria2可选择开启QUIC流量混淆（需要客户端支持）**

### **使用以下命令运行脚本**

**快捷命令：sb**

```
(curl -LfsS https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -o /usr/local/bin/sb || wget -q https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/singbox.sh -O /usr/local/bin/sb) && chmod +x /usr/local/bin/sb && sb
```
## **使用方法**
- **Clash客户端配置文件位于/usr/local/etc/sing-box/clash.yaml，初始文件仅保证基础使用。**
- **菜单选择查看节点分享链接，复制粘贴导入v2rayN即可使用**

## **脚本支持的节点类型**
- **VLESS (REALITY)，推荐直连使用**
- **VLESS (tcp)，推荐落地使用**
- **Hysteria2（自签证书），推荐直连使用**
- **TUICv5（自签证书），推荐直连使用**
- **Shadowsocks (aes-256-gcm，2022-blake3-aes-128-gcm)，推荐落地使用**
- **Socks5，推荐落地使用**

## **更多yaml配置文件模板，可做参考**
- **[Release](https://github.com/0xdabiaoge/singbox-lite/releases)**

## **版本更新说明**
**2025.09.27更新要点：**

**1、增加自定义IP地址的输入，可手动输入IP地址或者直接使用机器默认IP，应对某些情况下需要手动修改节点链接。**
**2、新增AnyTLS节点协议的搭建。**


## **免责声明**
- **本项目仅供学习与技术交流，请在下载后 24 小时内删除，禁止用于商业或非法目的。**
- **使用本脚本所搭建的服务，请严格遵守部署服务器所在地、服务提供商和用户所在国家/地区的相关法律法规。**
- **对于任何因不当使用本脚本而导致的法律纠纷或后果，脚本作者及维护者概不负责。**
